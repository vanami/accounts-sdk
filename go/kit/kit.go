// Package kit is the Go SDK a Vanami service uses to trust the SaaS kit
// (planning 39 §4.3): Middleware verifies the kit's JWT access tokens
// against its published keys (JWKS) — offline, no call back to the kit per
// request — and puts the caller's identity in the request context.
//
//	v, err := kit.NewVerifier(ctx, "https://accounts.vanami.com", "mail")
//	http.Handle("/v1/", v.Middleware(api))
//	...
//	who, _ := kit.FromContext(r.Context()) // who.UserID, who.AccountID, who.Role
package kit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Identity is who made the request.
type Identity struct {
	UserID    string   // the token's subject: one Vanami ID across services
	AccountID string   // the account (customer workspace) the token speaks for
	Role      string   // owner | admin | member in that account
	Scopes    []string // OAuth scopes granted
	ClientID  string   // the service the token was issued to
	ExpiresAt time.Time
	// Plan and Entitlements are the account's in this service when the token
	// was issued (it lives 15 minutes; Client.Entitlements is real time).
	Plan         string
	Entitlements map[string]any
}

// Limit answers an integer entitlement ("domains": 10). ok is false when
// the plan does not grant it at all.
func (id Identity) Limit(key string) (n int64, ok bool) {
	switch v := id.Entitlements[key].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	}
	return 0, false
}

// Has answers a boolean entitlement ("catch_all": true); an integer limit
// above zero counts as granted.
func (id Identity) Has(key string) bool {
	switch v := id.Entitlements[key].(type) {
	case bool:
		return v
	default:
		n, ok := id.Limit(key)
		return ok && n > 0
	}
}

// ErrNotEntitled is what Require answers when the plan does not allow it.
var ErrNotEntitled = errors.New("kit: the account's plan does not allow this")

// Require checks that the caller (from Middleware) may use n units of an
// integer entitlement in total, or that a flag is set (n ignored for flags):
//
//	if err := kit.Require(ctx, "domains", existing+1); err != nil { … 402 … }
func Require(ctx context.Context, key string, n int64) error {
	id, ok := FromContext(ctx)
	if !ok {
		return ErrNoToken
	}
	if b, isFlag := id.Entitlements[key].(bool); isFlag {
		if b {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrNotEntitled, key)
	}
	limit, ok := id.Limit(key)
	if !ok || n > limit {
		return fmt.Errorf("%w: %s (needs %d, plan allows %d)", ErrNotEntitled, key, n, limit)
	}
	return nil
}

var (
	ErrNoToken      = errors.New("kit: no bearer token")
	ErrInvalidToken = errors.New("kit: invalid token")
)

// Verifier checks access tokens for one audience (the service's client id).
type Verifier struct {
	issuer   string
	audience string
	jwksURI  string
	client   *http.Client
	leeway   time.Duration
	now      func() time.Time

	mu        sync.RWMutex
	keys      map[string]jose.JSONWebKey
	lastFetch time.Time
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithHTTPClient sets the client used for discovery and JWKS.
func WithHTTPClient(c *http.Client) Option { return func(v *Verifier) { v.client = c } }

// WithClock replaces the clock (tests).
func WithClock(now func() time.Time) Option { return func(v *Verifier) { v.now = now } }

// NewVerifier reads the kit's discovery document and keys. issuer is the
// kit's URL; audience is this service's client id.
func NewVerifier(ctx context.Context, issuer, audience string, opts ...Option) (*Verifier, error) {
	v := &Verifier{issuer: strings.TrimRight(issuer, "/"), audience: audience,
		client: &http.Client{Timeout: 10 * time.Second}, leeway: 30 * time.Second, now: time.Now}
	for _, o := range opts {
		o(v)
	}
	if audience == "" {
		return nil, errors.New("kit: audience (the service's client id) is required")
	}
	var disc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, v.issuer+"/.well-known/openid-configuration", &disc); err != nil {
		return nil, fmt.Errorf("kit: discovery: %w", err)
	}
	if strings.TrimRight(disc.Issuer, "/") != v.issuer || disc.JWKSURI == "" {
		return nil, fmt.Errorf("kit: discovery: issuer %q / jwks_uri %q do not match %q", disc.Issuer, disc.JWKSURI, v.issuer)
	}
	v.jwksURI = disc.JWKSURI
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Verifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

func (v *Verifier) refresh(ctx context.Context) error {
	var set jose.JSONWebKeySet
	if err := v.getJSON(ctx, v.jwksURI, &set); err != nil {
		return fmt.Errorf("kit: jwks: %w", err)
	}
	keys := map[string]jose.JSONWebKey{}
	for _, k := range set.Keys {
		if k.Use == "" || k.Use == "sig" {
			keys[k.KeyID] = k
		}
	}
	v.mu.Lock()
	v.keys, v.lastFetch = keys, v.now()
	v.mu.Unlock()
	return nil
}

// key finds a key by id, refetching the set (at most once a minute) when the
// kit has rotated to a key this process has not seen.
func (v *Verifier) key(ctx context.Context, kid string) (jose.JSONWebKey, bool) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	stale := v.now().Sub(v.lastFetch) > time.Minute
	v.mu.RUnlock()
	if ok || !stale {
		return k, ok
	}
	if err := v.refresh(ctx); err != nil {
		return jose.JSONWebKey{}, false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	k, ok = v.keys[kid]
	return k, ok
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type claims struct {
	Issuer       string         `json:"iss"`
	Subject      string         `json:"sub"`
	Audience     audience       `json:"aud"`
	Expiry       int64          `json:"exp"`
	NotBefore    int64          `json:"nbf"`
	ClientID     string         `json:"client_id"`
	Scope        string         `json:"scope"`
	AccountID    string         `json:"account_id"`
	AccountRole  string         `json:"account_role"`
	Plan         string         `json:"plan"`
	Entitlements map[string]any `json:"entitlements"`
}

// Verify checks a raw access token: RS256 signature by a published kit key,
// issuer, audience, expiry. Every failure is ErrInvalidToken (wrapped with
// the reason for logs; never shown to the caller).
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(jws.Signatures) != 1 {
		return Identity{}, fmt.Errorf("%w: unparseable", ErrInvalidToken)
	}
	key, ok := v.key(ctx, jws.Signatures[0].Header.KeyID)
	if !ok {
		return Identity{}, fmt.Errorf("%w: unknown signing key", ErrInvalidToken)
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: bad signature", ErrInvalidToken)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Identity{}, fmt.Errorf("%w: claims", ErrInvalidToken)
	}
	now := v.now()
	switch {
	case strings.TrimRight(c.Issuer, "/") != v.issuer:
		return Identity{}, fmt.Errorf("%w: issuer %q", ErrInvalidToken, c.Issuer)
	case !slices.Contains(c.Audience, v.audience):
		return Identity{}, fmt.Errorf("%w: not for audience %q", ErrInvalidToken, v.audience)
	case c.Expiry == 0 || now.After(time.Unix(c.Expiry, 0).Add(v.leeway)):
		return Identity{}, fmt.Errorf("%w: expired", ErrInvalidToken)
	case c.NotBefore != 0 && now.Add(v.leeway).Before(time.Unix(c.NotBefore, 0)):
		return Identity{}, fmt.Errorf("%w: not yet valid", ErrInvalidToken)
	case c.Subject == "" || c.AccountID == "":
		return Identity{}, fmt.Errorf("%w: no subject/account", ErrInvalidToken)
	}
	return Identity{UserID: c.Subject, AccountID: c.AccountID, Role: c.AccountRole,
		Scopes: strings.Fields(c.Scope), ClientID: c.ClientID, ExpiresAt: time.Unix(c.Expiry, 0),
		Plan: c.Plan, Entitlements: c.Entitlements}, nil
}

type ctxKey struct{}

// FromContext returns the identity Middleware stored.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// WithIdentity stores an identity (tests of handlers behind Middleware).
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// Middleware rejects requests without a valid kit access token (401) and
// passes the caller's Identity to next.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		raw, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || raw == "" {
			unauthorized(w, "")
			return
		}
		id, err := v.Verify(r.Context(), raw)
		if err != nil {
			unauthorized(w, "invalid_token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

func unauthorized(w http.ResponseWriter, code string) {
	v := `Bearer realm="kit"`
	if code != "" {
		v += `, error="` + code + `"`
	}
	w.Header().Set("WWW-Authenticate", v)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

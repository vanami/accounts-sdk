package kit_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/hallsten/saas-kit/sdk/go/kit"
)

// fakeKit serves discovery + JWKS and signs tokens like the kit does.
type fakeKit struct {
	t    *testing.T
	ts   *httptest.Server
	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
}

func newFakeKit(t *testing.T) *fakeKit {
	f := &fakeKit{t: t, keys: map[string]*rsa.PrivateKey{}}
	f.addKey("k1")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.ts.URL, "jwks_uri": f.ts.URL + "/keys"}) //nolint:errcheck
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var set jose.JSONWebKeySet
		for id, k := range f.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{KeyID: id, Use: "sig", Algorithm: "RS256", Key: &k.PublicKey})
		}
		json.NewEncoder(w).Encode(set) //nolint:errcheck
	})
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeKit) addKey(id string) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.keys[id] = k
	f.mu.Unlock()
}

func (f *fakeKit) sign(kid string, claims map[string]any) string {
	f.mu.Lock()
	k := f.keys[kid]
	f.mu.Unlock()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k},
		(&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		f.t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	obj, err := s.Sign(b)
	if err != nil {
		f.t.Fatal(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

func (f *fakeKit) claims(mod func(map[string]any)) map[string]any {
	c := map[string]any{"iss": f.ts.URL, "sub": "u1", "aud": []string{"mail"}, "exp": time.Now().Add(time.Minute).Unix(),
		"client_id": "mail", "scope": "openid email", "account_id": "a1", "account_role": "admin"}
	if mod != nil {
		mod(c)
	}
	return c
}

func TestVerify(t *testing.T) {
	f := newFakeKit(t)
	ctx := context.Background()
	v, err := kit.NewVerifier(ctx, f.ts.URL, "mail")
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Verify(ctx, f.sign("k1", f.claims(nil)))
	if err != nil || id.UserID != "u1" || id.AccountID != "a1" || id.Role != "admin" || len(id.Scopes) != 2 {
		t.Fatalf("valid token: %+v %v", id, err)
	}
	for name, mod := range map[string]func(map[string]any){
		"expired":       func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"no expiry":     func(c map[string]any) { delete(c, "exp") },
		"wrong issuer":  func(c map[string]any) { c["iss"] = "https://evil.example" },
		"wrong aud":     func(c map[string]any) { c["aud"] = "other" },
		"not yet valid": func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
		"no account":    func(c map[string]any) { delete(c, "account_id") },
	} {
		if _, err := v.Verify(ctx, f.sign("k1", f.claims(mod))); !errors.Is(err, kit.ErrInvalidToken) {
			t.Errorf("%s: want ErrInvalidToken, got %v", name, err)
		}
	}
	// A single-string audience is accepted.
	if _, err := v.Verify(ctx, f.sign("k1", f.claims(func(c map[string]any) { c["aud"] = "mail" }))); err != nil {
		t.Errorf("string aud: %v", err)
	}
	// alg=none / HS256 are never accepted.
	if _, err := v.Verify(ctx, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9."); !errors.Is(err, kit.ErrInvalidToken) {
		t.Errorf("alg none: %v", err)
	}
}

func TestKeyRotationIsPickedUp(t *testing.T) {
	f := newFakeKit(t)
	ctx := context.Background()
	clock := time.Now()
	v, err := kit.NewVerifier(ctx, f.ts.URL, "mail", kit.WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	f.addKey("k2")
	tok := f.sign("k2", f.claims(func(c map[string]any) { c["exp"] = clock.Add(time.Hour).Unix() }))
	// Within a minute of the last fetch the set is not refetched (no
	// stampede on garbage kids)…
	if _, err := v.Verify(ctx, tok); !errors.Is(err, kit.ErrInvalidToken) {
		t.Fatalf("an unseen key within the refetch window: %v", err)
	}
	// …after it, the rotated key is fetched and the token verifies.
	clock = clock.Add(2 * time.Minute)
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
}

package kit

// Lifecycle events (planning 39 §4.1): the kit posts them to the URL in the
// product's manifest (`webhooks`), signed with the product's secret
// (`accounts webhook-secret <product>`). Delivery is at least once, so a
// handler dedupes on Event.ID; a non-2xx answer is retried with backoff.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Event types.
const (
	EventAccountCreated      = "account.created"      // the account used this service for the first time
	EventMemberAdded         = "member.added"         // someone joined the account
	EventMemberRoleChanged   = "member.role_changed"  // a member's role changed
	EventMemberRemoved       = "member.removed"       // a member left or was removed
	EventSubscriptionChanged = "subscription.changed" // the account's plan or status here changed
)

// SignatureHeader carries "t=<unix>,v1=<hex hmac-sha256 of "t.body">".
const SignatureHeader = "Kit-Signature"

// EventTolerance is how old a signature may be (replay window).
const EventTolerance = 5 * time.Minute

// ErrInvalidSignature: the body was not signed by the kit with this secret,
// or the signature is too old.
var ErrInvalidSignature = errors.New("kit: invalid event signature")

// Event is one lifecycle event.
type Event struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Product   string          `json:"product"`
	CreatedAt time.Time       `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

// MemberData is the data of the member.* events.
type MemberData struct {
	AccountID    string `json:"account_id"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	PreviousRole string `json:"previous_role,omitempty"` // member.role_changed
}

// AccountData is the data of account.created.
type AccountData struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
	UserID      string `json:"user_id"` // who first signed in to the service for it
	Role        string `json:"role"`
}

// SubscriptionData is the data of subscription.changed.
type SubscriptionData struct {
	AccountID string `json:"account_id"`
	Product   string `json:"product"`
	Plan      string `json:"plan"`
	Status    string `json:"status"`
	Entitled  bool   `json:"entitled"` // the plan's entitlements apply
	// Entitlements are those that now apply: the plan's while entitled, else
	// the free plan's — for work done without a user's token.
	Entitlements      map[string]any `json:"entitlements,omitempty"`
	CurrentPeriodEnd  *time.Time     `json:"current_period_end,omitempty"`
	CancelAtPeriodEnd bool           `json:"cancel_at_period_end"`
}

// VerifyEvent checks the signature header against the raw body and decodes
// the event.
func VerifyEvent(secret, header string, body []byte, now time.Time) (Event, error) {
	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sigs = append(sigs, v)
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(sigs) == 0 {
		return Event{}, ErrInvalidSignature
	}
	if d := now.Sub(time.Unix(sec, 0)); d > EventTolerance || d < -EventTolerance {
		return Event{}, ErrInvalidSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	ok := false
	for _, s := range sigs {
		if got, err := hex.DecodeString(s); err == nil && hmac.Equal(got, want) {
			ok = true
		}
	}
	if !ok {
		return Event{}, ErrInvalidSignature
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil || ev.ID == "" || ev.Type == "" {
		return Event{}, ErrInvalidSignature
	}
	return ev, nil
}

// EventHandler verifies each delivery and hands it to fn: a bad signature
// answers 400 (not retried usefully), an error from fn 500 (the kit
// retries), success 204.
func EventHandler(secret string, fn func(ctx context.Context, ev Event) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		ev, err := VerifyEvent(secret, r.Header.Get(SignatureHeader), body, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := fn(r.Context(), ev); err != nil {
			http.Error(w, "event not handled", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

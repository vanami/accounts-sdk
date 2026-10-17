package kit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBillingURL(t *testing.T) {
	c := &Client{Issuer: "https://accounts.test/", Product: "mail"}
	for _, tc := range []struct{ account, plan, interval, want string }{
		{"a/1", "", "", "https://accounts.test/account/organisations/a%2F1/billing/mail"},
		{"a1", "business", "year", "https://accounts.test/account/organisations/a1/billing/mail/change?interval=year&plan=business"},
		{"a1", "pro", "", "https://accounts.test/account/organisations/a1/billing/mail/change?interval=month&plan=pro"},
	} {
		if got := c.BillingURL(tc.account, tc.plan, tc.interval); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
	if got := (&Client{Issuer: "https://accounts.test"}).BillingURL("a1", "", ""); got != "" {
		t.Errorf("no product: %q", got)
	}
}

// The first organisation, for a user who has none (doc 07 D-465).
func TestCreateAccount(t *testing.T) {
	var got struct{ method, auth, name string }
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/accounts" {
			http.NotFound(w, r)
			return
		}
		got.method, got.auth = r.Method, r.Header.Get("Authorization")
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"accounts":[{"id":"a1","name":"Acme","role":"owner","current":false}]}`)) //nolint:errcheck
			return
		}
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in) //nolint:errcheck
		got.name = in["name"]
		if in["name"] == "Full" {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"error":"too_many_accounts","message":"…"}`)) //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"a2","name":"Acme","role":"owner"}`)) //nolint:errcheck
	}))
	defer ts.Close()
	c := &Client{Issuer: ts.URL}
	ctx := context.Background()
	a, err := c.CreateAccount(ctx, "tok", "Acme")
	if err != nil || a.ID != "a2" || a.Role != "owner" || got.method != http.MethodPost || got.auth != "Bearer tok" || got.name != "Acme" {
		t.Fatalf("create: %+v %v %+v", a, err, got)
	}
	if _, err := c.CreateAccount(ctx, "tok", "Full"); !IsTooManyAccounts(err) || IsSeatLimit(err) {
		t.Fatalf("too many: %v", err)
	}
	if IsTooManyAccounts(&APIError{Status: 409, Message: "seat_limit"}) {
		t.Fatal("a seat limit is not too many accounts")
	}
	as, err := c.Accounts(ctx, "tok")
	if err != nil || len(as) != 1 || as[0].ID != "a1" || got.method != http.MethodGet {
		t.Fatalf("accounts: %+v %v", as, err)
	}
}

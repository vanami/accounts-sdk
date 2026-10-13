package kit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

const catalogueJSON = `{"product":"isms","name":{"en":"ISMS"},
"plans":[{"key":"free","name":{"en":"free"},"free":true,"prices":[],"entitlements":{"export":false},"usage":{}},
 {"key":"pro","name":{"en":"Pro","sv":"Pro"},"free":false,"prices":[{"interval":"year","amount":499000,"currency":"sek","tax_behavior":"exclusive"}],
  "entitlements":{"export":true},"trial_days":30,"usage":{}}],
"meters":[],"entitlements":[{"key":"export","kind":"flag","label":{"en":"Export","sv":"Export"}}],
"permissions":[{"key":"isms.read","label":{"en":"isms.read"}},{"key":"isms.write","label":{"en":"Edit the register","sv":"Redigera registret"}}],
"roles":[{"key":"editor","label":{"en":"Editor","sv":"Redigerare"},"permissions":["isms.read","isms.write"]}],
"default_roles":{"owner":"editor","admin":"editor","member":"editor"},"over_limit":"block_new"}`

func TestCatalogueIsReadCachedAndRevalidated(t *testing.T) {
	var calls, revalidations atomic.Int32
	var down atomic.Bool
	var cacheControl atomic.Value
	cacheControl.Store("public, max-age=60")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if r.URL.Path != "/api/v1/products/isms" || r.Header.Get("Authorization") != "" {
			http.Error(w, `{"error":"no such product"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Cache-Control", cacheControl.Load().(string))
		if r.Header.Get("If-None-Match") == `"v1"` {
			revalidations.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Write([]byte(catalogueJSON)) //nolint:errcheck
	}))
	defer ts.Close()
	ctx := context.Background()
	c := &Client{Issuer: ts.URL + "/", Product: "isms"}

	// A minute's max-age: one call for many reads.
	p, err := c.Catalogue(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	pro, ok := p.Plan("pro")
	if !ok || pro.TrialDays != 30 || pro.Entitlements["export"] != true {
		t.Fatalf("pro: %+v", pro)
	}
	if pr, ok := pro.Price("year"); !ok || pr.Amount != 499000 || pr.Currency != "sek" {
		t.Fatalf("pro's yearly price: %+v", pr)
	}
	if r, ok := p.Role("editor"); !ok || Label(r.Label, "sv-SE") != "Redigerare" || Label(r.Label, "de") != "Editor" ||
		!slices.Equal(r.Permissions, []string{"isms.read", "isms.write"}) {
		t.Fatalf("editor: %+v", r)
	}
	if _, err := c.Catalogue(ctx, "isms"); err != nil || calls.Load() != 1 {
		t.Fatalf("a fresh catalogue is not fetched again: %v, %d calls", err, calls.Load())
	}

	// Without a max-age it is revalidated each time by its ETag, and a 304
	// keeps the body; with the kit down, the last answer is used.
	cacheControl.Store("no-cache")
	productCache.Range(func(k, v any) bool { v.(*cachedProduct).expires = time.Time{}; return true })
	for i := 0; i < 2; i++ {
		if p, err := c.Catalogue(ctx, ""); err != nil || p.Product != "isms" {
			t.Fatalf("revalidated: %v", err)
		}
	}
	if revalidations.Load() != 2 || calls.Load() != 3 {
		t.Fatalf("revalidated by ETag each time: %d of %d calls", revalidations.Load(), calls.Load())
	}
	down.Store(true)
	if p, err := c.Catalogue(ctx, ""); err != nil || p.Product != "isms" {
		t.Fatalf("the last answer while the kit is down: %v", err)
	}
	if _, err := c.Catalogue(ctx, "nope"); err == nil {
		t.Fatal("a product never fetched, with the kit down: an error")
	}
	if _, err := (&Client{Issuer: ts.URL}).Catalogue(ctx, ""); err == nil {
		t.Fatal("no product: an error")
	}
}

func TestUnknownKeys(t *testing.T) {
	var p Product
	if err := json.Unmarshal([]byte(catalogueJSON), &p); err != nil {
		t.Fatal(err)
	}
	got := p.Unknown(Keys{Permissions: []string{"isms.write", "isms.wrte"}, Entitlements: []string{"export", "approvals"},
		Plans: []string{"pro", "business"}, Meters: []string{"documents"}})
	want := []string{"permission isms.wrte", "entitlement approvals", "plan business", "meter documents"}
	if !slices.Equal(got, want) {
		t.Fatalf("unknown keys: %v", got)
	}
	if got := p.Unknown(Keys{Permissions: []string{"isms.read"}, Entitlements: []string{"export"}, Plans: []string{"free"}}); got != nil {
		t.Fatalf("all declared: %v", got)
	}
}

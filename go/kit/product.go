package kit

// The product catalogue (doc 07 D-450): what a service sells and who may do
// what — plans, prices, usage terms, roles, permissions and entitlements,
// with their names per language — read from the kit instead of a copy of
// the manifest in the service.
//
//	p, err := c.Catalogue(ctx, "")    // c.Product's catalogue
//	pro, _ := p.Plan("pro")
//	kit.Label(pro.Name, "sv")          // "Pro"
//	if bad := p.Unknown(kit.Keys{Permissions: []string{"isms.write"}}); len(bad) > 0 { ... }

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Product is one service's catalogue, as the kit's manifest says now.
type Product struct {
	Product      string            `json:"product"`
	Name         map[string]string `json:"name"`
	Plans        []Plan            `json:"plans"`
	Meters       []Meter           `json:"meters"`
	Entitlements []Entitlement     `json:"entitlements"`
	Permissions  []Permission      `json:"permissions"`
	Roles        []Role            `json:"roles"`
	// DefaultRoles: each account role's role in the service (owner, admin,
	// member) until an owner or admin assigns another.
	DefaultRoles map[string]string `json:"default_roles"`
	OverLimit    string            `json:"over_limit"` // block_new | read_only
}

// Plan is one tier. Free: the plan every account has without a subscription.
type Plan struct {
	Key          string            `json:"key"`
	Name         map[string]string `json:"name"`
	Free         bool              `json:"free"`
	Prices       []Price           `json:"prices"`
	Entitlements map[string]any    `json:"entitlements"` // float64 limits, bool flags
	TrialDays    int               `json:"trial_days,omitempty"`
	AutoTrial    bool              `json:"auto_trial,omitempty"`
	Seats        *PlanSeats        `json:"seats,omitempty"`
	Usage        map[string]Terms  `json:"usage"`
}

// Price is one recurring price, in minor units (9900 = 99.00).
type Price struct {
	Interval    string `json:"interval"` // month | year
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`     // ISO 4217, lower case
	TaxBehavior string `json:"tax_behavior"` // exclusive (VAT on top) | inclusive
	SeatAmount  int64  `json:"seat_amount,omitempty"`
}

// PlanSeats is how members count on a plan (G169).
type PlanSeats struct {
	Pricing   string   `json:"pricing"` // flat | per_seat
	Included  int      `json:"included,omitempty"`
	Max       int      `json:"max,omitempty"` // 0 = no cap
	FreeRoles []string `json:"free_roles,omitempty"`
}

// Terms is a plan's terms for one meter: included per calendar month, and
// the price of each unit beyond (0 = none: a cap).
type Terms struct {
	Included int64 `json:"included"`
	Overage  int64 `json:"overage,omitempty"`
}

type Meter struct {
	Key  string            `json:"key"`
	Name map[string]string `json:"name"`
}

type Entitlement struct {
	Key   string            `json:"key"`
	Kind  string            `json:"kind"` // limit | flag
	Label map[string]string `json:"label"`
}

type Permission struct {
	Key   string            `json:"key"`
	Label map[string]string `json:"label"`
}

type Role struct {
	Key         string            `json:"key"`
	Label       map[string]string `json:"label"`
	Permissions []string          `json:"permissions"`
}

// Plan finds one plan.
func (p Product) Plan(key string) (Plan, bool) {
	for _, pl := range p.Plans {
		if pl.Key == key {
			return pl, true
		}
	}
	return Plan{}, false
}

// Role finds one role.
func (p Product) Role(key string) (Role, bool) {
	for _, r := range p.Roles {
		if r.Key == key {
			return r, true
		}
	}
	return Role{}, false
}

// Price is the plan's price for an interval.
func (pl Plan) Price(interval string) (Price, bool) {
	for _, pr := range pl.Prices {
		if pr.Interval == interval {
			return pr, true
		}
	}
	return Price{}, false
}

// Label picks a name in locale ("sv", "pt-BR"), then its language ("pt"),
// then English. The kit gives every name at least "en".
func Label(name map[string]string, locale string) string {
	if s := name[locale]; s != "" {
		return s
	}
	if lang, _, ok := strings.Cut(locale, "-"); ok && name[lang] != "" {
		return name[lang]
	}
	return name["en"]
}

// Keys are what a service's code checks by name.
type Keys struct {
	Permissions  []string
	Entitlements []string
	Plans        []string
	Meters       []string
}

// Unknown lists the keys the catalogue does not declare, e.g.
// "permission isms.wrte" — a typo, or something the manifest no longer
// has. Check it at start-up or in CI.
func (p Product) Unknown(k Keys) []string {
	var out []string
	check := func(kind string, want []string, has func(string) bool) {
		for _, key := range want {
			if !has(key) {
				out = append(out, kind+" "+key)
			}
		}
	}
	check("permission", k.Permissions, func(s string) bool {
		return slices.ContainsFunc(p.Permissions, func(x Permission) bool { return x.Key == s })
	})
	check("entitlement", k.Entitlements, func(s string) bool {
		return slices.ContainsFunc(p.Entitlements, func(x Entitlement) bool { return x.Key == s })
	})
	check("plan", k.Plans, func(s string) bool { _, ok := p.Plan(s); return ok })
	check("meter", k.Meters, func(s string) bool {
		return slices.ContainsFunc(p.Meters, func(x Meter) bool { return x.Key == s })
	})
	return out
}

// productCache keeps each catalogue as the kit last answered it, for as
// long as its Cache-Control allows, then revalidates it by its ETag.
var productCache sync.Map // url → *cachedProduct

type cachedProduct struct {
	mu      sync.Mutex
	etag    string
	body    []byte
	expires time.Time
}

// Catalogue is a service's catalogue; product "" = c.Product. Public — no
// token — and cached as the kit allows (a minute), so calling it per
// request is fine. If the kit cannot be reached, the last answer is used.
func (c *Client) Catalogue(ctx context.Context, product string) (Product, error) {
	if product == "" {
		product = c.Product
	}
	if product == "" {
		return Product{}, fmt.Errorf("kit: Catalogue needs a product or Client.Product")
	}
	u := strings.TrimRight(c.Issuer, "/") + "/api/v1/products/" + url.PathEscape(product)
	v, _ := productCache.LoadOrStore(u, &cachedProduct{})
	e := v.(*cachedProduct)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.body == nil || time.Now().After(e.expires) {
		if err := c.fetchProduct(ctx, u, e); err != nil && e.body == nil {
			return Product{}, err
		}
	}
	var p Product
	return p, json.Unmarshal(e.body, &p)
}

func (c *Client) fetchProduct(ctx context.Context, u string, e *cachedProduct) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if e.etag != "" {
		req.Header.Set("If-None-Match", e.etag)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	switch {
	case res.StatusCode == http.StatusNotModified && e.body != nil:
	case res.StatusCode == http.StatusOK:
		e.body, e.etag = raw, res.Header.Get("ETag")
	default:
		var ae struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &ae) //nolint:errcheck
		return &APIError{Status: res.StatusCode, Message: ae.Error}
	}
	e.expires = time.Now().Add(maxAge(res.Header.Get("Cache-Control")))
	return nil
}

// maxAge reads Cache-Control's max-age (0 when absent).
func maxAge(cc string) time.Duration {
	for _, d := range strings.Split(cc, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(d), "max-age="); ok {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}

package kit

// Usage (slice 3c): report what an account used, per meter declared in the
// service's manifest; read this month's use against the plan.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"time"
)

// MeterUsage is an account's use of one meter this calendar month (UTC).
type MeterUsage struct {
	Meter    string `json:"meter"`
	Used     int64  `json:"used"`
	Included int64  `json:"included"`
	// Overage: minor units per unit beyond Included, billed monthly (0 =
	// none: Included is a cap the service enforces — see Remaining).
	Overage  int64  `json:"overage,omitempty"`
	Currency string `json:"currency,omitempty"`
	// Limited: the plan caps this meter; false = unlimited, or overage billed.
	Limited     bool      `json:"limited"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
}

// Remaining answers how many units are left under a cap; limited is false
// when the meter has no cap (unlimited, or billed beyond Included).
func (u MeterUsage) Remaining() (n int64, limited bool) {
	if !u.Limited {
		return 0, false
	}
	return max(u.Included-u.Used, 0), true
}

// ReportUsage reports that account used quantity of meter. The key makes a
// retry safe: the kit keeps each key once (recorded = false for a repeat).
// A service call: Client.Product and Client.ServiceSecret sign it.
func (c *Client) ReportUsage(ctx context.Context, accountID, meter string, quantity int64, idempotencyKey string) (recorded bool, err error) {
	var out struct {
		Recorded bool `json:"recorded"`
	}
	err = c.call(ctx, "POST", "/api/v1/usage", "", map[string]any{"account_id": accountID, "meter": meter,
		"quantity": quantity, "idempotency_key": idempotencyKey}, &out)
	return out.Recorded, err
}

// Usage answers this month's use per meter for the token's account.
func (c *Client) Usage(ctx context.Context, accessToken string) ([]MeterUsage, error) {
	var out struct {
		Meters []MeterUsage `json:"meters"`
	}
	err := c.call(ctx, "GET", "/api/v1/usage", accessToken, nil, &out)
	return out.Meters, err
}

// UsageFor is Usage for any account of the service (a signed service call).
func (c *Client) UsageFor(ctx context.Context, accountID string) ([]MeterUsage, error) {
	var out struct {
		Meters []MeterUsage `json:"meters"`
	}
	err := c.call(ctx, "GET", "/api/v1/usage?"+url.Values{"account_id": {accountID}}.Encode(), "", nil, &out)
	return out.Meters, err
}

// signService: Kit-Signature for a service call — over the kit's own
// string, so it never passes for an event signature or the other way round.
func signService(secret string, t time.Time, method, uri string, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + ".kit-service." + method + " " + uri + "\n"))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

package kit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls the kit's API on behalf of a signed-in user, with that
// user's access token (the one Middleware verified).
type Client struct {
	Issuer string
	HTTP   *http.Client // nil = 15s timeout
}

// CheckoutRequest starts a subscription purchase. The return URLs must be
// on the service's own origins (its manifest).
type CheckoutRequest struct {
	Plan       string `json:"plan"`
	Interval   string `json:"interval"` // month | year
	SuccessURL string `json:"success_url"`
	CancelURL  string `json:"cancel_url"`
}

// Entitlements is the kit's real-time answer for the token's account and
// service.
type Entitlements struct {
	Product           string         `json:"product"`
	Plan              string         `json:"plan"`
	Status            string         `json:"status"`
	Entitlements      map[string]any `json:"entitlements"`
	CurrentPeriodEnd  *time.Time     `json:"current_period_end,omitempty"`
	CancelAtPeriodEnd bool           `json:"cancel_at_period_end,omitempty"`
}

// APIError is a non-2xx answer from the kit.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("kit: %d: %s", e.Status, e.Message) }

// Checkout answers the Stripe Checkout URL to redirect the buyer to.
func (c *Client) Checkout(ctx context.Context, accessToken string, in CheckoutRequest) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	err := c.call(ctx, http.MethodPost, "/api/v1/checkout", accessToken, in, &out)
	return out.URL, err
}

// Portal answers the Stripe Customer Portal URL (change plan, card,
// cancel, receipts).
func (c *Client) Portal(ctx context.Context, accessToken, returnURL string) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	err := c.call(ctx, http.MethodPost, "/api/v1/portal", accessToken, map[string]string{"return_url": returnURL}, &out)
	return out.URL, err
}

// Entitlements answers the account's plan and entitlements now.
func (c *Client) Entitlements(ctx context.Context, accessToken string) (Entitlements, error) {
	var out Entitlements
	err := c.call(ctx, http.MethodGet, "/api/v1/entitlements", accessToken, nil, &out)
	return out, err
}

func (c *Client) call(ctx context.Context, method, path, token string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Issuer, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
	if res.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &e) //nolint:errcheck
		return &APIError{Status: res.StatusCode, Message: e.Error}
	}
	return json.Unmarshal(raw, out)
}

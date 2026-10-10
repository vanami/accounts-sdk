package kit

import "testing"

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

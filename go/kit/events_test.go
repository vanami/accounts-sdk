package kit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"
)

func sign(secret string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyEvent(t *testing.T) {
	now := time.Now()
	body := []byte(`{"id":"e1","type":"member.added","product":"svc","created_at":"2026-10-01T10:00:00Z","data":{"user_id":"u1"}}`)
	ev, err := VerifyEvent("kwh_s", sign("kwh_s", now, body), body, now)
	if err != nil || ev.ID != "e1" || ev.Type != EventMemberAdded || ev.Product != "svc" {
		t.Fatalf("valid: %+v %v", ev, err)
	}
	// A rotated secret: any one matching v1 is enough.
	if _, err := VerifyEvent("kwh_s", "t="+strconv.FormatInt(now.Unix(), 10)+",v1=00ff,"+sign("kwh_s", now, body)[len("t=1234567890,"):], body, now); err != nil {
		t.Fatalf("second v1: %v", err)
	}
	tampered := append([]byte(nil), body...)
	tampered[10] = 'X'
	for name, c := range map[string]struct {
		secret, header string
		body           []byte
	}{
		"wrong secret": {"other", sign("kwh_s", now, body), body},
		"tampered":     {"kwh_s", sign("kwh_s", now, body), tampered},
		"stale":        {"kwh_s", sign("kwh_s", now.Add(-EventTolerance-time.Second), body), body},
		"future":       {"kwh_s", sign("kwh_s", now.Add(EventTolerance+time.Second), body), body},
		"no header":    {"kwh_s", "", body},
		"no v1":        {"kwh_s", "t=" + strconv.FormatInt(now.Unix(), 10), body},
	} {
		if _, err := VerifyEvent(c.secret, c.header, c.body, now); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

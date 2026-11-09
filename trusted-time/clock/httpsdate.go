package clock

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// HTTPSDate reads the Date header of an HTTPS response. TLS authenticates
// the server and binds the response to this connection, so the host can
// delay or drop it but not forge or replay it. Resolution is one second.
//
// The reading comes from the first response of URL, whatever its status
// (a 302 or a 404 has a Date too). A redirect is never followed: its
// target is another host, which nobody chose as a time source, and may be
// plain HTTP (TIME-SOURCE-01) or a host the egress does not allow
// (TIME-SOURCE-02).
//
// Caveat: Go checks certificate validity against the local clock, which
// the host controls. A host that winds the local clock back could make an
// expired or revoked certificate pass; it would still need that
// certificate's private key.
type HTTPSDate struct {
	URL    string
	Client *http.Client // nil: http.DefaultClient. Set a custom dialer for vsock-proxy.
}

func (h *HTTPSDate) Name() string { return "https-date(" + h.URL + ")" }

func (h *HTTPSDate) Fetch(ctx context.Context) (time.Time, error) {
	c := h.Client
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, h.URL, nil)
	if err != nil {
		return time.Time{}, err
	}
	if req.URL.Scheme != "https" {
		return time.Time{}, errors.New("clock: https-date needs an https URL")
	}
	resp, err := noRedirect(c).Do(req)
	if err != nil {
		return time.Time{}, err
	}
	resp.Body.Close()
	if resp.TLS == nil {
		return time.Time{}, errors.New("clock: https-date: the answer did not come over TLS")
	}
	d := resp.Header.Get("Date")
	if d == "" {
		return time.Time{}, fmt.Errorf("clock: https-date: no Date header (status %d)", resp.StatusCode)
	}
	return http.ParseTime(d)
}

// noRedirect is a copy of c that returns the first response as it is, a
// redirect included, instead of following it.
func noRedirect(c *http.Client) *http.Client {
	cc := *c
	cc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cc
}

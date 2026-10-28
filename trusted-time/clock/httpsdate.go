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
	resp, err := httpsOnly(c).Do(req)
	if err != nil {
		return time.Time{}, err
	}
	resp.Body.Close()
	// The Date must come from a TLS answer: a redirect may lead elsewhere
	// (TIME-SOURCE-01).
	if resp.TLS == nil || resp.Request == nil || resp.Request.URL.Scheme != "https" {
		return time.Time{}, errors.New("clock: https-date: the final answer did not come over TLS")
	}
	d := resp.Header.Get("Date")
	if d == "" {
		return time.Time{}, fmt.Errorf("clock: no Date header (status %d)", resp.StatusCode)
	}
	return http.ParseTime(d)
}

// httpsOnly is a copy of c that follows a redirect only to an https URL.
// Go's default policy follows https to http, and the Date of a plain HTTP
// answer is anyone's to set (TIME-SOURCE-01). c's own redirect policy, if
// any, still runs after this check.
func httpsOnly(c *http.Client) *http.Client {
	cc := *c
	next := c.CheckRedirect
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("clock: https-date: refused a redirect to %s://%s", req.URL.Scheme, req.URL.Host)
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("clock: https-date: stopped after 10 redirects")
		}
		return nil
	}
	return &cc
}

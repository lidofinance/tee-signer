package azure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// retryDelay is the wait before the first retry; it doubles each time.
// Tests shorten it.
var retryDelay = time.Second

const (
	httpAttempts = 4
	// maxBody caps every response the runner reads (the sidecar caps at the
	// same 1 MiB).
	maxBody = 1 << 20
)

// newClient is an HTTP client for the Azure endpoints. It ignores proxy
// variables: the instance metadata service is link-local, and nothing here
// should go through a proxy the group's environment names.
func newClient(timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Timeout: timeout, Transport: t}
}

// retryable says whether a status is worth another try: timeouts, rate
// limits and server errors.
func retryable(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

// httpDo sends the request that build makes, up to httpAttempts times. It
// retries transport errors and the statuses for which retryOn (or, if nil,
// retryable) is true. It returns the body of a 2xx answer, and an error for
// anything else.
func httpDo(ctx context.Context, c *http.Client, build func() (*http.Request, error), retryOn func(int) bool) ([]byte, error) {
	if retryOn == nil {
		retryOn = retryable
	}
	if c == nil {
		c = http.DefaultClient
	}
	var last error
	for attempt := 0; attempt < httpAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w (last error: %v)", ctx.Err(), last)
			case <-time.After(retryDelay << (attempt - 1)):
			}
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req.WithContext(ctx))
		if err != nil {
			last = err
			continue
		}
		body, rerr := readLimited(resp.Body, maxBody)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if rerr != nil {
				return nil, rerr
			}
			return body, nil
		}
		last = fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Host+req.URL.Path, resp.Status, snippet(body))
		if !retryOn(resp.StatusCode) {
			return nil, last
		}
	}
	return nil, last
}

// httpGetWithRetry is httpDo for a GET with headers.
func httpGetWithRetry(ctx context.Context, c *http.Client, url string, headers map[string]string, retryOn func(int) bool) ([]byte, error) {
	return httpDo(ctx, c, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req, nil
	}, retryOn)
}

// snippet shortens a response body for an error message.
func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// readLimited reads at most max bytes of r.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}

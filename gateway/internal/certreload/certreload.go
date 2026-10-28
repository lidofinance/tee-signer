// Package certreload keeps the gateway's client certificate and key
// current without a restart. A Watcher reads both files at every poll. A
// pair that changed takes effect only if it parses, the key belongs to
// the certificate, and the certificate is valid at the gateway's clock.
// Anything else leaves the pair in force and is logged once per content,
// however often it is polled.
package certreload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// The log messages, also counted by the tests.
const (
	msgReloaded = "client certificate reloaded"
	msgRefused  = "client certificate on disk refused, keeping the one in force"
	msgExpired  = "client certificate expired and no valid replacement on disk"
)

// ErrExpired is the error of Usable once the certificate in force expired.
var ErrExpired = errors.New("client certificate expired")

// Pair is a checked certificate and key. A Pair never changes.
type Pair struct {
	cert    tls.Certificate
	certPEM []byte
	keyPEM  []byte
	digest  [32]byte
	gen     uint64
}

// Gen numbers the pairs of a Watcher: 1 for the one read at start, one
// more for each swap.
func (p *Pair) Gen() uint64 { return p.gen }

// NotAfter is the end of the certificate's validity.
func (p *Pair) NotAfter() time.Time { return p.cert.Leaf.NotAfter }

// NotBefore is the start of the certificate's validity.
func (p *Pair) NotBefore() time.Time { return p.cert.Leaf.NotBefore }

// Serial is the certificate's serial number in decimal.
func (p *Pair) Serial() string { return p.cert.Leaf.SerialNumber.String() }

// Files calls f with two paths that read as the certificate and the key
// of p: pipes under /dev/fd. The key reaches the reader without a copy on
// disk, and content written to the configured files after the check
// never does. The paths work only during f, and f need not read them.
func (p *Pair) Files(f func(certPath, keyPath string) error) error {
	c, err := feed(p.certPEM)
	if err != nil {
		return err
	}
	defer c.Close()
	k, err := feed(p.keyPEM)
	if err != nil {
		return err
	}
	defer k.Close()

	return f(fdPath(c), fdPath(k))
}

// feed returns the read end of a pipe that yields b and then ends. A
// reader that stops early, or none, ends the writer when the caller
// closes the read end.
func feed(b []byte) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		_, _ = w.Write(b)
		_ = w.Close()
	}()

	return r, nil
}

func fdPath(f *os.File) string { return fmt.Sprintf("/dev/fd/%d", f.Fd()) }

// Watcher holds the pair in force and polls the files for a new one.
type Watcher struct {
	certPath, keyPath string
	log               *slog.Logger
	now               func() time.Time

	mu  sync.Mutex
	cur *Pair
	// refused is the digest of the last content refused and logged.
	refused [32]byte
	// expiredLogged is when the expiry of cur was last logged.
	expiredLogged time.Time
	subs          []chan struct{}
	stats         Stats
}

// Stats counts the polls by result.
type Stats struct {
	// Reloaded counts the polls that swapped in a new pair, Refused those
	// that refused the content on disk (each poll of the same content
	// again), and Unchanged those that found the pair in force.
	Reloaded, Refused, Unchanged uint64
	// Since is when the pair in force took effect: the start or the last
	// swap.
	Since time.Time
}

// New reads the pair at certPath and keyPath. It fails if the pair does
// not pass the checks of a reload.
func New(certPath, keyPath string, log *slog.Logger) (*Watcher, error) {
	return newWatcher(certPath, keyPath, log, time.Now)
}

func newWatcher(certPath, keyPath string, log *slog.Logger, now func() time.Time) (*Watcher, error) {
	w := &Watcher{certPath: certPath, keyPath: keyPath, log: log, now: now}
	certPEM, keyPEM, err := w.read()
	if err != nil {
		return nil, err
	}
	p, err := w.check(certPEM, keyPEM, now())
	if err != nil {
		return nil, err
	}
	p.gen = 1
	w.cur = p
	w.stats.Since = now()

	return w, nil
}

func (w *Watcher) read() (certPEM, keyPEM []byte, err error) {
	if certPEM, err = os.ReadFile(w.certPath); err != nil {
		return nil, nil, fmt.Errorf("client_cert: %w", err)
	}
	if keyPEM, err = os.ReadFile(w.keyPath); err != nil {
		return nil, nil, fmt.Errorf("client_key: %w", err)
	}

	return certPEM, keyPEM, nil
}

// check parses a pair and checks that the key belongs to the certificate
// and that the certificate is valid at now.
func (w *Watcher) check(certPEM, keyPEM []byte, now time.Time) (*Pair, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("client_cert %s and client_key %s: %w", w.certPath, w.keyPath, err)
	}
	leaf := cert.Leaf
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("client_cert %s: serial %s is not valid before %s", w.certPath, leaf.SerialNumber,
			leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("client_cert %s: serial %s expired at %s", w.certPath, leaf.SerialNumber,
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	return &Pair{cert: cert, certPEM: certPEM, keyPEM: keyPEM, digest: digest(certPEM, keyPEM)}, nil
}

func digest(certPEM, keyPEM []byte) [32]byte {
	h := sha256.New()
	for _, b := range [][]byte{certPEM, keyPEM} {
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(b))))
		h.Write(b)
	}

	return [32]byte(h.Sum(nil))
}

// Current is the pair in force.
func (w *Watcher) Current() *Pair {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.cur
}

// Stats returns the poll counts so far.
func (w *Watcher) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.stats
}

// Subscribe returns a channel that receives after each swap. It holds one
// notice; a subscriber that is slow misses none but may get two as one.
func (w *Watcher) Subscribe() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch := make(chan struct{}, 1)
	w.subs = append(w.subs, ch)

	return ch
}

// Usable returns an error naming the certificate file once the pair in
// force has expired.
func (w *Watcher) Usable() error {
	p := w.Current()
	if w.now().After(p.NotAfter()) {
		return fmt.Errorf("%w: %s (serial %s) expired at %s and the file holds no valid replacement", ErrExpired,
			w.certPath, p.Serial(), p.NotAfter().UTC().Format(time.RFC3339))
	}

	return nil
}

// Poll reads the files once. It swaps in a changed pair that passes the
// checks and reports whether it did. A refused content is logged the
// first time Poll sees it; it is checked again at every poll, so a
// certificate that is not valid yet takes effect once it is. While the
// pair in force is expired, Poll logs that once a minute.
func (w *Watcher) Poll() bool {
	now := w.now()
	certPEM, keyPEM, err := w.read()
	var d [32]byte
	if err != nil {
		d = sha256.Sum256([]byte(err.Error()))
	} else {
		d = digest(certPEM, keyPEM)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	swapped := false
	switch {
	case err == nil && d == w.cur.digest:
		w.refused = [32]byte{}
		w.stats.Unchanged++
	default:
		var p *Pair
		if err == nil {
			p, err = w.check(certPEM, keyPEM, now)
		}
		if err != nil {
			w.stats.Refused++
			if d != w.refused {
				w.refused = d
				w.log.Error(msgRefused, "err", err.Error(), "serial", w.cur.Serial(),
					"not_after", w.cur.NotAfter().UTC().Format(time.RFC3339))
			}

			break
		}
		p.gen = w.cur.gen + 1
		w.cur, w.refused, w.expiredLogged, swapped = p, [32]byte{}, time.Time{}, true
		w.stats.Reloaded++
		w.stats.Since = now
		w.log.Info(msgReloaded, "cert", w.certPath, "serial", p.Serial(), "not_after", p.NotAfter().UTC().Format(time.RFC3339),
			"generation", p.gen)
		for _, ch := range w.subs {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	if now.After(w.cur.NotAfter()) && (w.expiredLogged.IsZero() || now.Sub(w.expiredLogged) >= time.Minute) {
		w.expiredLogged = now
		w.log.Error(msgExpired, "cert", w.certPath, "serial", w.cur.Serial(),
			"not_after", w.cur.NotAfter().UTC().Format(time.RFC3339))
	}

	return swapped
}

// Run polls every interval until ctx ends.
func (w *Watcher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Poll()
		}
	}
}

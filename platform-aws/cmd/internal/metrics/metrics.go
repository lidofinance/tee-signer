// Package metrics writes the Prometheus text format and serves it over
// plain HTTP, for the tools on the parent instance (forwarder, hostagent).
// It is hand-written to keep new dependencies out of the module.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Writer builds one scrape in the text exposition format 0.0.4. Samples
// of one metric must come one after the other: HELP and TYPE are written
// before the first sample of each name only.
type Writer struct {
	b    strings.Builder
	seen map[string]bool
}

// Counter writes a counter sample. labels are name, value pairs.
func (w *Writer) Counter(name, help string, v float64, labels ...string) {
	w.sample(name, "counter", help, v, labels)
}

// Gauge writes a gauge sample. labels are name, value pairs.
func (w *Writer) Gauge(name, help string, v float64, labels ...string) {
	w.sample(name, "gauge", help, v, labels)
}

// Info writes a gauge of value 1 that carries its data in labels.
func (w *Writer) Info(name, help string, labels ...string) {
	w.sample(name, "gauge", help, 1, labels)
}

// String is the text written so far.
func (w *Writer) String() string { return w.b.String() }

func (w *Writer) sample(name, typ, help string, v float64, labels []string) {
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	if !w.seen[name] {
		w.seen[name] = true
		fmt.Fprintf(&w.b, "# HELP %s %s\n# TYPE %s %s\n", name, helpEscaper.Replace(help), name, typ)
	}
	w.b.WriteString(name)
	if len(labels) > 0 {
		w.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				w.b.WriteByte(',')
			}
			fmt.Fprintf(&w.b, "%s=\"%s\"", labels[i], labelEscaper.Replace(labels[i+1]))
		}
		w.b.WriteByte('}')
	}
	w.b.WriteByte(' ')
	w.b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
	w.b.WriteByte('\n')
}

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

// Handler serves GET /metrics with the samples collect writes.
func Handler(collect func(w *Writer)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(rw http.ResponseWriter, r *http.Request) {
		var w Writer
		collect(&w)
		rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		rw.Write([]byte(w.String()))
	})
	return mux
}

// CheckAddr refuses a listen address that is not loopback, unless
// allowRemote: the endpoint has no authentication.
func CheckAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if allowRemote || host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("metrics address %q is not loopback; the endpoint has no authentication (allow it with -metrics-allow-remote)", addr)
}

// Start listens on addr (after CheckAddr) and serves collect at /metrics
// until ctx ends.
func Start(ctx context.Context, addr string, allowRemote bool, collect func(w *Writer), log *slog.Logger) error {
	if err := CheckAddr(addr, allowRemote); err != nil {
		return err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: Handler(collect), ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) && log != nil {
			log.Error("metrics server", "err", err)
		}
	}()
	if log != nil {
		log.Info("metrics", "addr", l.Addr().String())
	}
	return nil
}

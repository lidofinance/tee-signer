// Package metrics is a small Prometheus registry: counters, gauges and
// histograms with labels, and families read at each scrape. It writes the
// Prometheus text format, version 0.0.4, and uses the standard library
// only.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ContentType is the content type of the text format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Registry holds metric families and writes them in the order they were
// added.
type Registry struct {
	mu    sync.Mutex
	fams  []family
	names map[string]bool
}

type family interface{ write(b *strings.Builder) }

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{names: map[string]bool{}} }

func (r *Registry) add(name string, f family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[name] {
		panic("metrics: " + name + " added twice")
	}
	r.names[name] = true
	r.fams = append(r.fams, f)
}

// WriteTo writes every family in the text format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	fams := append([]family(nil), r.fams...)
	r.mu.Unlock()
	var b strings.Builder
	for _, f := range fams {
		f.write(&b)
	}
	n, err := io.WriteString(w, b.String())

	return int64(n), err
}

// ServeHTTP answers every request with the families in the text format.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", ContentType)
	_, _ = r.WriteTo(w)
}

type desc struct {
	name, help, typ string
	labels          []string
}

// The text format escapes a backslash and a newline in help texts, and a
// double quote too in label values.
var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	valueEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

func (d *desc) header(b *strings.Builder) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", d.name, helpEscaper.Replace(d.help), d.name, d.typ)
}

func (d *desc) check(values []string) {
	if len(values) != len(d.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d label values, got %d", d.name, len(d.labels), len(values)))
	}
}

// line writes one sample: name{label="value",...} v. le, if not empty, is
// a histogram bucket's upper bound, the last label.
func line(b *strings.Builder, name string, labels, values []string, le string, v float64) {
	b.WriteString(name)
	if len(labels) > 0 || le != "" {
		b.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(b, `%s="%s"`, l, valueEscaper.Replace(values[i]))
		}
		if le != "" {
			if len(labels) > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(b, `le="%s"`, le)
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(formatFloat(v))
	b.WriteByte('\n')
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}

	return strconv.FormatFloat(v, 'g', -1, 64)
}

// point is one series: its label values and its value, or for a
// histogram its counts per bucket (not cumulative), sum and count.
type point struct {
	values []string
	v      float64
	counts []uint64
	sum    float64
	n      uint64
}

// vec is a family of series, one per combination of label values.
type vec struct {
	desc
	mu     sync.Mutex
	series map[string]*point
}

func newVec(name, help, typ string, labels []string) vec {
	return vec{desc: desc{name: name, help: help, typ: typ, labels: labels}, series: map[string]*point{}}
}

// at returns the series of values, made on first use. The caller holds mu.
func (v *vec) at(values []string) *point {
	v.check(values)
	key := strings.Join(values, "\xff")
	p := v.series[key]
	if p == nil {
		p = &point{values: append([]string(nil), values...)}
		v.series[key] = p
	}

	return p
}

// sorted returns the series in the order of their label values. The
// caller holds mu.
func (v *vec) sorted() []*point {
	keys := make([]string, 0, len(v.series))
	for k := range v.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*point, len(keys))
	for i, k := range keys {
		out[i] = v.series[k]
	}

	return out
}

func (v *vec) value(values []string) float64 {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.at(values).v
}

func (v *vec) write(b *strings.Builder) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.header(b)
	for _, p := range v.sorted() {
		line(b, v.name, v.labels, p.values, "", p.v)
	}
}

// CounterVec is a counter per combination of label values.
type CounterVec struct{ vec }

// Counter adds a counter family.
func (r *Registry) Counter(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{newVec(name, help, "counter", labels)}
	r.add(name, c)

	return c
}

// Inc adds 1 to the series of values.
func (c *CounterVec) Inc(values ...string) { c.Add(1, values...) }

// Add adds d, which must not be negative, to the series of values.
func (c *CounterVec) Add(d float64, values ...string) {
	if d < 0 {
		panic("metrics: " + c.name + ": a counter does not go down")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at(values).v += d
}

// Value is the value of the series, 0 before its first use.
func (c *CounterVec) Value(values ...string) float64 { return c.value(values) }

// GaugeVec is a gauge per combination of label values.
type GaugeVec struct{ vec }

// Gauge adds a gauge family.
func (r *Registry) Gauge(name, help string, labels ...string) *GaugeVec {
	g := &GaugeVec{newVec(name, help, "gauge", labels)}
	r.add(name, g)

	return g
}

// Set sets the series of values to v.
func (g *GaugeVec) Set(v float64, values ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.at(values).v = v
}

// Value is the value of the series, 0 before its first use.
func (g *GaugeVec) Value(values ...string) float64 { return g.value(values) }

// HistogramVec is a histogram per combination of label values.
type HistogramVec struct {
	vec
	bounds []float64
}

// Histogram adds a histogram family with these bucket upper bounds, in
// increasing order. The +Inf bucket is implied.
func (r *Registry) Histogram(name, help string, bounds []float64, labels ...string) *HistogramVec {
	if !sort.Float64sAreSorted(bounds) {
		panic("metrics: " + name + ": bucket bounds out of order")
	}
	h := &HistogramVec{newVec(name, help, "histogram", labels), append([]float64(nil), bounds...)}
	r.add(name, h)

	return h
}

// Observe adds v to the series of values.
func (h *HistogramVec) Observe(v float64, values ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.at(values)
	if p.counts == nil {
		p.counts = make([]uint64, len(h.bounds))
	}
	if i := sort.SearchFloat64s(h.bounds, v); i < len(h.bounds) {
		p.counts[i]++
	}
	p.sum += v
	p.n++
}

// Count is the number of observations of the series.
func (h *HistogramVec) Count(values ...string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.at(values).n
}

func (h *HistogramVec) write(b *strings.Builder) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.header(b)
	for _, p := range h.sorted() {
		var cum uint64
		for i, bound := range h.bounds {
			if p.counts != nil {
				cum += p.counts[i]
			}
			line(b, h.name+"_bucket", h.labels, p.values, formatFloat(bound), float64(cum))
		}
		line(b, h.name+"_bucket", h.labels, p.values, "+Inf", float64(p.n))
		line(b, h.name+"_sum", h.labels, p.values, "", p.sum)
		line(b, h.name+"_count", h.labels, p.values, "", float64(p.n))
	}
}

// funcFamily is a family whose samples come from collect at each scrape.
type funcFamily struct {
	desc
	collect func(emit func(v float64, values ...string))
}

// Func adds a family of type typ ("gauge" or "counter") whose samples
// collect gives at each scrape, one emit per series.
func (r *Registry) Func(name, help, typ string, labels []string, collect func(emit func(v float64, values ...string))) {
	r.add(name, &funcFamily{desc{name: name, help: help, typ: typ, labels: labels}, collect})
}

func (f *funcFamily) write(b *strings.Builder) {
	var pts []*point
	f.collect(func(v float64, values ...string) {
		f.check(values)
		pts = append(pts, &point{values: append([]string(nil), values...), v: v})
	})
	sort.SliceStable(pts, func(i, j int) bool {
		return strings.Join(pts[i].values, "\xff") < strings.Join(pts[j].values, "\xff")
	})
	f.header(b)
	for _, p := range pts {
		line(b, f.name, f.labels, p.values, "", p.v)
	}
}

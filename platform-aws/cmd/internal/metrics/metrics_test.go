package metrics

import (
	"io"
	"net/http/httptest"
	"testing"
)

func TestText(t *testing.T) {
	var w Writer
	w.Counter("a_total", "Line one\nback\\slash.", 3, "kind", "x")
	w.Counter("a_total", "ignored", 4, "kind", `q"b\n`+"\n")
	w.Gauge("b", "B.", 1.5)
	w.Info("c_info", "C.", "id", "i-1", "cid", "16")
	want := `# HELP a_total Line one\nback\\slash.
# TYPE a_total counter
a_total{kind="x"} 3
a_total{kind="q\"b\\n\n"} 4
# HELP b B.
# TYPE b gauge
b 1.5
# HELP c_info C.
# TYPE c_info gauge
c_info{id="i-1",cid="16"} 1
`
	if got := w.String(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestHandler(t *testing.T) {
	h := Handler(func(w *Writer) { w.Gauge("up", "Up.", 1) })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != 200 || string(body) != "# HELP up Up.\n# TYPE up gauge\nup 1\n" {
		t.Fatalf("%d %q", rec.Code, body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatal(ct)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/metrics", nil))
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
}

func TestCheckAddr(t *testing.T) {
	for _, a := range []string{"127.0.0.1:9101", "[::1]:9101", "localhost:9101", "127.0.0.2:1"} {
		if err := CheckAddr(a, false); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{":9101", "0.0.0.0:9101", "10.0.0.5:9101", "example.com:9101", "nonsense"} {
		if err := CheckAddr(a, false); err == nil {
			t.Errorf("%s accepted", a)
		}
	}
	if err := CheckAddr("0.0.0.0:9101", true); err != nil {
		t.Error(err)
	}
}

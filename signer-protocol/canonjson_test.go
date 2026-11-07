package backend

import (
	"strings"
	"testing"
)

func TestCanonicalJSON(t *testing.T) {
	for in, want := range map[string]string{
		`{"b":1,"a":{"y":[3,1,2],"x":null}}`:     `{"a":{"x":null,"y":[3,1,2]},"b":1}`,
		" { \"a\" : [ true , false ] }\n":        `{"a":[true,false]}`,
		`{"n":12345678901234567890123,"f":1.50}`: `{"f":1.50,"n":12345678901234567890123}`,
		`{"s":"<a&b>\u0041\/\u00e9\u2028"}`:      `{"s":"<a&b>A/é\u2028"}`,
		`{"e":{},"l":[]}`:                        `{"e":{},"l":[]}`,
		`"x"`:                                    `"x"`,
		"{\"s\":\"a\xffb\"}":                     "{\"s\":\"a\ufffdb\"}",
		`{"s":"\u2029"}`:                         `{"s":"\u2029"}`,
	} {
		got, err := CanonicalJSON([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("CanonicalJSON(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{``, `{`, `{"a":1}{}`, `{"a":1} x`, `{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `[1,]`, strings.Repeat("[", 70) + strings.Repeat("]", 70)} {
		if got, err := CanonicalJSON([]byte(in)); err == nil {
			t.Errorf("CanonicalJSON(%q) = %q, want an error", in, got)
		}
	}
}

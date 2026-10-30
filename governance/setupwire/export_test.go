package setupwire

import "testing"

// FormatRefusals runs every case of TestSetupRefusals through format and
// fails the test for each one it accepts. The human form lives in
// governance/setuptext, which this package cannot import, so the external
// test package format_test.go passes it in.
func FormatRefusals(t *testing.T, format func(*Setup) error) {
	for _, c := range setupRefusals(t) {
		if err := format(c.setup(t)); err == nil {
			t.Errorf("%s: format accepted it", c.name)
		}
	}
}

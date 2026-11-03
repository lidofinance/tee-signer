//go:build !verifierselect

package main

import (
	"bytes"
	"strings"
	"testing"
)

const realDoc = "../../testdata/nitro/blocky-nitrite/nitro_attestation.b64"

const realPCR0 = "e72a46ca80a260fb044a125442f0c7e331813bcbaf9724d9f3857758992766f2d65710a27aa94ae3949dd54e7c9fe86a"

func TestCLINitroRealDocument(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-platform", "nitro", "-in", realDoc, "-at", "2024-09-07T14:37:40Z", "-max-age", "1m", "-pcr", "0=" + realPCR0}, &out, &errb)
	if code != 0 || !strings.Contains(out.String(), realPCR0) {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	wrong := "0=" + strings.Repeat("00", 47) + "01"
	code = run([]string{"-platform", "nitro", "-in", realDoc, "-at", "2024-09-07T14:37:40Z", "-max-age", "1m", "-pcr", wrong}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "measurement mismatch") {
		t.Fatalf("exit %d\n%s", code, errb.String())
	}
	errb.Reset()
	code = run([]string{"-platform", "nitro", "-in", realDoc, "-max-age", "1m", "-pcr", "0=" + realPCR0}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "certificate chain not trusted") {
		t.Fatalf("today: exit %d\n%s", code, errb.String())
	}
}

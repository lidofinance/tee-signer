package attest

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// maxErrText bounds the error text a verifier builds from a peer's
// document: wire.MaxDetail, the limit the runner already keeps for a
// refusal's detail.
const maxErrText = 1024

// checkErrText fails the test when err is nil, longer than maxErrText or
// carries a raw control byte.
func checkErrText(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted", what)
	}
	msg := err.Error()
	if len(msg) > maxErrText {
		t.Errorf("%s: error text of %d bytes, at most %d: unsigned peer bytes are echoed whole (starts %.80q)", what, len(msg), maxErrText, msg)
	}
	for i := 0; i < len(msg); i++ {
		if c := msg[i]; c < 0x20 || c == 0x7f {
			t.Errorf("%s: raw byte %#02x at %d of the error text: it reaches the operator's terminal as sent", what, c, i)
			break
		}
	}
}

// The verifiers put fields that no
// signature covers yet into their errors, whole: a Nitro digest text of
// about 1 MiB gives a 4 MiB error, which the gateway logs twice per failed
// request; a token header's alg is printed raw, control bytes included.
// The errors must stay short and printable.
func TestUnsignedFieldsInErrorsAreBounded(t *testing.T) {
	t.Run("nitro digest", func(t *testing.T) {
		// The digest check runs before the chain and signature checks, so
		// the document needs no valid signature.
		payload, err := cbor.Marshal(map[string]any{"module_id": "i-x", "timestamp": uint64(1),
			"digest": strings.Repeat("\x1b", 1<<20-200)})
		if err != nil {
			t.Fatal(err)
		}
		prot, _ := cbor.Marshal(map[int]int{1: coseAlgES384})
		doc, err := cbor.Marshal([]any{prot, map[int]int{}, payload, make([]byte, 96)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyNitro(doc, NitroOptions{AcceptAnyPCRs: true, Nonce: []byte("n")})
		wantErr(t, err, ErrFormat)
		checkErrText(t, "nitro digest", err)
	})

	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	o := MAAOptions{Issuer: maaIssuer, Keys: keySet(t, jwksFor(t, "k", testRSA(t, 0), false)), Now: now,
		ComplianceStatus: ComplianceACI, HostData: []string{maaHostData}, RuntimeData: maaRuntime}
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	token := func(header string) string {
		tok := b64(header) + "." + b64("{}") + "." + b64("x")
		if len(tok) > maxToken {
			t.Fatalf("test token of %d bytes is over the token limit", len(tok))
		}
		return tok
	}
	t.Run("jwt alg", func(t *testing.T) {
		_, err := VerifyMAA(token(`{"alg":"`+strings.Repeat(`\u001b[2J\n`, 14000)+`","kid":"k"}`), o)
		checkErrText(t, "jwt alg", err)
	})
	t.Run("jwt kid", func(t *testing.T) {
		_, err := VerifyMAA(token(`{"alg":"RS256","kid":"`+strings.Repeat(`\u0001`, 31000)+`"}`), o)
		checkErrText(t, "jwt kid", err)
	})
}

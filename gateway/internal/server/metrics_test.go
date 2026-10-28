package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/gateway/internal/backend"
	"github.com/lidofinance/tee-signer/gateway/internal/metrics"
	"github.com/lidofinance/tee-signer/gateway/internal/policy"
	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// Each sign request whose body parsed counts once, under its type and
// result.
func TestMetricsRequests(t *testing.T) {
	pk, _ := parsePubkey(pubHex)
	f := &fakeSigner{key: pk}
	pol, err := policy.New([]string{allowedFeeRecipient})
	if err != nil {
		t.Fatal(err)
	}
	h, err := eth2.NewHasher("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	chain := signing.Chain{Hasher: h, SlotsPerEpoch: 32, GenesisForkVersion: phase0.Version{}}
	srv := httptest.NewServer(New(f, pol, chain, slog.New(slog.NewTextHandler(io.Discard, nil)), 0).WithMetrics(m).Handler())
	t.Cleanup(srv.Close)

	target := uint64(411400)
	att := func(err error) {
		t.Helper()
		f.err = err
		target++
		post(t, srv, pubHex, "application/json", attestationBody(target))
	}
	att(nil)
	att(nil)
	att(&backend.DeniedError{Detail: "slashing"})
	att(fmt.Errorf("2 of 3 before the deadline: %w", context.DeadlineExceeded))
	att(errors.New("not enough signatures"))
	f.err = nil
	post(t, srv, "0x"+fmt.Sprintf("%096x", 1), "application/json", attestationBody(target+1))
	post(t, srv, pubHex, "application/json", registrationBody("0x2222222222222222222222222222222222222222", pubHex))
	post(t, srv, pubHex, "application/json", `{"type":"NOT_A_TYPE"}`)

	for _, c := range []struct {
		typ, result string
		want        float64
	}{
		{"ATTESTATION", "ok", 2},
		{"ATTESTATION", "denied", 1},
		{"ATTESTATION", "timeout", 1},
		{"ATTESTATION", "error", 1},
		{"ATTESTATION", "unknown_key", 1},
		{"VALIDATOR_REGISTRATION", "policy", 1},
	} {
		if got := m.Requests.Value(c.typ, c.result); got != c.want {
			t.Errorf("%s %s = %v, want %v", c.typ, c.result, got, c.want)
		}
	}
	var b strings.Builder
	_, _ = m.Registry.WriteTo(&b)
	if strings.Contains(b.String(), "NOT_A_TYPE") {
		t.Error("a type the gateway did not parse is a label value")
	}
}

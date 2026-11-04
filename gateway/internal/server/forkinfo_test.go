package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/gateway/internal/policy"
	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

const hoodiGVR = "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"

// newHoodiServer is a test server pinned to Hoodi as the README's example
// config pins it: forks to Fulu, no BPO entries.
func newHoodiServer(t *testing.T) (*httptest.Server, *fakeSigner) {
	t.Helper()
	pk, ok := parsePubkey(pubHex)
	if !ok {
		t.Fatal("bad test key")
	}
	f := &fakeSigner{key: pk}
	pol, err := policy.New([]string{allowedFeeRecipient})
	if err != nil {
		t.Fatal(err)
	}
	h, err := eth2.NewHasher("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	var root phase0.Root
	if err := root.UnmarshalJSON([]byte(strconv.Quote(hoodiGVR))); err != nil {
		t.Fatal(err)
	}
	pin := &signing.Pin{GenesisValidatorsRoot: root}
	for i, e := range []phase0.Epoch{0, 0, 0, 0, 0, 2048, 50688} {
		pin.Forks = append(pin.Forks, signing.ForkEpoch{Epoch: e, Version: phase0.Version{byte(i+1) << 4, 0, 0x09, 0x10}})
	}
	chain := signing.Chain{Hasher: h, SlotsPerEpoch: 32, GenesisForkVersion: phase0.Version{0x10, 0, 0x09, 0x10}, Pin: pin}
	srv := httptest.NewServer(New(f, pol, chain, slog.New(slog.NewTextHandler(io.Discard, nil)), 0).Handler())
	t.Cleanup(srv.Close)

	return srv, f
}

// hoodiAttestation is an attestation for target with fork_info from prev,
// cur and forkEpoch, in the shape Prysm sends.
func hoodiAttestation(prev, cur string, forkEpoch, target uint64) string {
	return fmt.Sprintf(`{"type":"ATTESTATION","signingRoot":null,"fork_info":{"fork":{"previous_version":"%s","current_version":"%s","epoch":"%d"},"genesis_validators_root":"%s"},
	"attestation":{"slot":"%d","index":"0","beacon_block_root":"0x%064x","source":{"epoch":"%d","root":"0x%064x"},"target":{"epoch":"%d","root":"0x%064x"}}}`,
		prev, cur, forkEpoch, hoodiGVR, target*32+5, 1, target-1, 2, target, 3)
}

// Prysm 7.3.1 sends the latest blob-parameter-only fork on Hoodi: previous
// and current version both Fulu, epoch 54016. The config has no BPO entry.
func TestPrysmBPOForkInfo(t *testing.T) {
	srv, f := newHoodiServer(t)
	for _, body := range []string{
		hoodiAttestation("0x70000910", "0x70000910", 54016, 54100),
		hoodiAttestation("0x70000910", "0x70000910", 52480, 53000),
		hoodiAttestation("0x60000910", "0x70000910", 50688, 54100),
	} {
		code, _, resp := post(t, srv, pubHex, "application/json", body)
		if code != http.StatusOK {
			t.Fatalf("got %d %s for %s", code, resp, body)
		}
		var root phase0.Root
		_ = root.UnmarshalJSON([]byte(strconv.Quote(hoodiGVR)))
		want, err := eth2.ComputeDomain(eth2.DomainBeaconAttester, phase0.Version{0x70, 0, 0x09, 0x10}, root)
		if err != nil || f.domain != want {
			t.Fatalf("domain %#x, want Fulu's %#x (%v)", f.domain, want, err)
		}
	}
	// The fork version must still be the schedule's: Electra in BPO form is refused.
	if code, _, resp := post(t, srv, pubHex, "application/json", hoodiAttestation("0x60000910", "0x60000910", 54016, 54100)); code != http.StatusBadRequest {
		t.Fatalf("Electra in BPO form: got %d %s, want 400", code, resp)
	}
}

// Every error status carries a JSON body {"code","message"} with a matching
// Content-Length, with or without an Accept header.
func TestErrorBodies(t *testing.T) {
	otherKey := "0x" + strings.Repeat("a1", 48)
	cases := []struct {
		name, key, body string
		err             error
		code            int
	}{
		{"fork_info off the schedule", pubHex, hoodiAttestation("0x60000910", "0x60000910", 54016, 54100), nil, 400},
		{"malformed body", pubHex, `{"type":"ATTESTATION"`, nil, 400},
		{"empty body", pubHex, ``, nil, 400},
		{"unknown key", otherKey, hoodiAttestation("0x70000910", "0x70000910", 54016, 54100), nil, 404},
		{"policy", pubHex, `{"type":"VOLUNTARY_EXIT","fork_info":{"fork":{"previous_version":"0x70000910","current_version":"0x70000910","epoch":"54016"},"genesis_validators_root":"` +
			hoodiGVR + `"},"voluntary_exit":{"epoch":"54100","validator_index":"7"}}`, nil, 412},
		{"signers fail", pubHex, hoodiAttestation("0x70000910", "0x70000910", 54016, 54100), fmt.Errorf("not enough signatures"), 500},
	}
	for _, c := range cases {
		for _, accept := range []string{"", "application/json", "text/plain"} {
			t.Run(c.name+"/"+accept, func(t *testing.T) {
				srv, f := newHoodiServer(t)
				f.err = c.err
				req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/eth2/sign/"+c.key, strings.NewReader(c.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				if accept != "" {
					req.Header.Set("Accept", accept)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != c.code {
					t.Fatalf("got %d %s, want %d", resp.StatusCode, b, c.code)
				}
				if resp.ContentLength <= 0 || resp.ContentLength != int64(len(b)) {
					t.Fatalf("Content-Length %d, body %d bytes", resp.ContentLength, len(b))
				}
				var e struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				}
				if resp.Header.Get("Content-Type") != contentTypeJSON || json.Unmarshal(b, &e) != nil || e.Code != c.code || e.Message == "" {
					t.Fatalf("error body %q %q", resp.Header.Get("Content-Type"), b)
				}
			})
		}
	}
}

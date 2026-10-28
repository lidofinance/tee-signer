package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/gateway/internal/backend"
	"github.com/lidofinance/tee-signer/gateway/internal/policy"
	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

const pubHex = "0xb7983759a799410899eb7344d4df1501a5af6adf8849c867c9f6277382ecea21b3317622eb23b51a373850566c407703"

const gvr = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

const forkInfo = `"fork_info":{"fork":{"previous_version":"0x05000000","current_version":"0x06000000","epoch":"411392"},"genesis_validators_root":"` + gvr + `"}`

const allowedFeeRecipient = "0x1111111111111111111111111111111111111111"

// fakeSigner records the signer message each call would send.
type fakeSigner struct {
	key    phase0.BLSPubKey
	calls  []string
	domain phase0.Domain
	err    error
}

func (f *fakeSigner) PublicKeys(context.Context) []phase0.BLSPubKey { return []phase0.BLSPubKey{f.key} }

func (f *fakeSigner) HasKey(_ context.Context, k phase0.BLSPubKey) bool { return k == f.key }

func (f *fakeSigner) sig() phase0.BLSSignature {
	var s phase0.BLSSignature
	s[0] = 0xab

	return s
}

func (f *fakeSigner) Sign(_ context.Context, _ phase0.BLSPubKey, job *signing.Job) (phase0.BLSSignature, error) {
	f.calls, f.domain = append(f.calls, backend.CallName(job)), job.Domain

	return f.sig(), f.err
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeSigner) {
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
	chain := signing.Chain{Hasher: h, SlotsPerEpoch: 32, GenesisForkVersion: phase0.Version{}}
	srv := httptest.NewServer(New(f, pol, chain, slog.New(slog.NewTextHandler(io.Discard, nil)), 0).Handler())
	t.Cleanup(srv.Close)

	return srv, f
}

func post(t *testing.T, srv *httptest.Server, key, accept, body string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/eth2/sign/"+key, strings.NewReader(body))
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
	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, resp.Header.Get("Content-Type"), string(b)
}

func attestationBody(target uint64) string {
	return fmt.Sprintf(`{"type":"ATTESTATION",%s,"attestation":{"slot":"%d","index":"0",
	"beacon_block_root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
	"source":{"epoch":"%d","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},
	"target":{"epoch":"%d","root":"0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89"}}}`,
		forkInfo, target*32, target-1, target)
}

func registrationBody(fee, pubkey string) string {
	return fmt.Sprintf(`{"type":"VALIDATOR_REGISTRATION","validator_registration":{"fee_recipient":"%s","gas_limit":"36000000","timestamp":"1760000000","pubkey":"%s"}}`, fee, pubkey)
}

func TestUpcheck(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/upcheck")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "OK" || resp.Header.Get("Content-Type") != contentTypeText {
		t.Fatalf("got %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
}

func TestPublicKeys(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/v1/eth2/publicKeys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var keys []string
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Type") != contentTypeJSON || len(keys) != 1 || keys[0] != pubHex {
		t.Fatalf("got %q %v", resp.Header.Get("Content-Type"), keys)
	}
}

// Web3Signer answers JSON when Accept has application/json or */*, text otherwise.
func TestSignResponseFormat(t *testing.T) {
	srv, _ := newTestServer(t)
	sig := fmt.Sprintf("%#x", (&fakeSigner{}).sig())
	cases := []struct {
		accept, wantType, wantBody string
	}{
		{"application/json", contentTypeJSON, `{"signature":"` + sig + `"}`},
		{"*/*", contentTypeJSON, `{"signature":"` + sig + `"}`},
		{"text/plain, application/json;q=0.5", contentTypeJSON, `{"signature":"` + sig + `"}`},
		{"text/plain", contentTypeText, sig},
		{"", contentTypeText, sig},
	}
	for i, c := range cases {
		code, ct, body := post(t, srv, pubHex, c.accept, attestationBody(uint64(411400+i)))
		if code != 200 || ct != c.wantType || body != c.wantBody {
			t.Errorf("Accept %q: got %d %q %q", c.accept, code, ct, body)
		}
	}
}

// Each request type goes out as its own signer message, under the domain
// the gateway computed.
func TestDispatchPerType(t *testing.T) {
	cases := []struct {
		name, body, call string
		domain           phase0.DomainType
	}{
		{"attestation", attestationBody(411400), "attestation", eth2.DomainBeaconAttester},
		{"block header", `{"type":"BLOCK_V2",` + forkInfo + `,"beacon_block":{"version":"FULU","block_header":{"slot":"13164545","proposer_index":"7",
			"parent_root":"0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
			"state_root":"0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
			"body_root":"0xa759d8029a69d4fdd8b3996086e9722983977e4efc1f12f4098ea3d93e868a6b"}}}`, "block", eth2.DomainBeaconProposer},
		{"randao", `{"type":"RANDAO_REVEAL",` + forkInfo + `,"randao_reveal":{"epoch":"411400"}}`, "root", eth2.DomainRandao},
		{"aggregation slot", `{"type":"AGGREGATION_SLOT",` + forkInfo + `,"aggregation_slot":{"slot":"13164545"}}`, "selection_proof", eth2.DomainSelectionProof},
		{"sync message", `{"type":"SYNC_COMMITTEE_MESSAGE",` + forkInfo + `,"sync_committee_message":{"beacon_block_root":"0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464","slot":"13164545"}}`, "sync_committee_message", eth2.DomainSyncCommittee},
		{"sync selection", `{"type":"SYNC_COMMITTEE_SELECTION_PROOF",` + forkInfo + `,"sync_aggregator_selection_data":{"slot":"13164545","subcommittee_index":"1"}}`, "sync_selection_proof", eth2.DomainSyncCommitteeSelectionProof},
		{"registration", registrationBody(allowedFeeRecipient, pubHex), "validator_registration", eth2.DomainApplicationBuilder},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, f := newTestServer(t)
			code, _, body := post(t, srv, pubHex, "application/json", c.body)
			if code != 200 {
				t.Fatalf("got %d %s", code, body)
			}
			if len(f.calls) != 1 || f.calls[0] != c.call {
				t.Fatalf("calls %v, want [%s]", f.calls, c.call)
			}
			if [4]byte(f.domain[:4]) != c.domain {
				t.Fatalf("domain %#x, want type %#x", f.domain, c.domain)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	other := "0x2222222222222222222222222222222222222222"
	otherKey := "0x" + strings.Repeat("a1", 48)
	cases := []struct {
		name, key, body string
		code            int
	}{
		{"voluntary exit", pubHex, `{"type":"VOLUNTARY_EXIT",` + forkInfo + `,"voluntary_exit":{"epoch":"411400","validator_index":"7"}}`, 412},
		{"fee recipient not allowlisted", pubHex, registrationBody(other, pubHex), 412},
		{"registration for another key", pubHex, registrationBody(allowedFeeRecipient, otherKey), 412},
		{"unknown key", otherKey, attestationBody(411400), 404},
		{"bad identifier", "0x1234", attestationBody(411400), 404},
		{"malformed body", pubHex, `{"type":"ATTESTATION"`, 400},
		{"unsupported type", pubHex, `{"type":"DEPOSIT","deposit":{}}`, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, f := newTestServer(t)
			code, ct, body := post(t, srv, c.key, "application/json", c.body)
			if code != c.code {
				t.Fatalf("got %d %s, want %d", code, body, c.code)
			}
			if len(f.calls) != 0 {
				t.Fatalf("signer was called: %v", f.calls)
			}
			var e struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if ct != contentTypeJSON || json.Unmarshal([]byte(body), &e) != nil || e.Code != c.code {
				t.Fatalf("error body %q %q", ct, body)
			}
		})
	}
}

func TestBackendErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{&backend.DeniedError{Detail: "not enough signatures: 0 signed, 3 denied, 0 failed, 0 errored"}, 412},
		{errors.New("not enough signatures: 1 signed, 0 denied, 0 failed, 2 errored"), 500},
		{backend.ErrUnknownKey, 404},
	}
	for _, c := range cases {
		srv, f := newTestServer(t)
		f.err = c.err
		if code, _, body := post(t, srv, pubHex, "", attestationBody(411400)); code != c.code {
			t.Errorf("%v: got %d %s, want %d", c.err, code, body, c.code)
		}
	}
}

// The identifier may come without 0x and in upper case (Web3Signer normalises it).
func TestIdentifierNormalisation(t *testing.T) {
	srv, _ := newTestServer(t)
	key := strings.ToUpper(strings.TrimPrefix(pubHex, "0x"))
	if code, _, body := post(t, srv, key, "", attestationBody(411400)); code != 200 {
		t.Fatalf("got %d %s", code, body)
	}
}

// With a Verifier, a signature that does not verify must not reach the client.
func TestVerifierRejectsBadSignature(t *testing.T) {
	pk, _ := parsePubkey(pubHex)
	pol, _ := policy.New(nil)
	h, _ := eth2.NewHasher("mainnet")
	chain := signing.Chain{Hasher: h, SlotsPerEpoch: 32}
	var gotRoot phase0.Root
	s := New(&fakeSigner{key: pk}, pol, chain, slog.New(slog.NewTextHandler(io.Discard, nil)), 0).
		WithVerifier(func(_ phase0.BLSPubKey, root phase0.Root, _ phase0.BLSSignature) error {
			gotRoot = root
			return errors.New("bad")
		})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	code, _, body := post(t, srv, pubHex, "application/json", attestationBody(411400))
	if code != 500 {
		t.Fatalf("got %d %s, want 500", code, body)
	}
	if gotRoot == (phase0.Root{}) {
		t.Fatal("verifier did not get the signing root")
	}
}

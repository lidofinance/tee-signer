package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/gateway/internal/policy"
	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// gloasServer is a test server on a chain with Gloas from epoch 0.
func gloasServer(t *testing.T) (*httptest.Server, *fakeSigner) {
	t.Helper()
	pk, _ := parsePubkey(pubHex)
	f := &fakeSigner{key: pk}
	pol, _ := policy.New([]string{allowedFeeRecipient})
	h, _ := eth2.NewHasher("mainnet")
	zero := phase0.Epoch(0)
	chain := signing.Chain{Hasher: h, SlotsPerEpoch: 32, GloasForkEpoch: &zero}
	ts := httptest.NewServer(New(f, pol, chain, slog.New(slog.NewTextHandler(io.Discard, nil)), 0).Handler())
	t.Cleanup(ts.Close)

	return ts, f
}

// Exits stay refused by policy before any call.
func TestExitRefusedBeforeTheSigners(t *testing.T) {
	srv, f := newTestServer(t)
	code, _, _ := post(t, srv, pubHex, "application/json", `{"type":"VOLUNTARY_EXIT",`+forkInfo+`,"voluntary_exit":{"epoch":"411400","validator_index":"1"}}`)
	if code != 412 || len(f.calls) != 0 {
		t.Fatalf("exit: status %d, calls %v", code, f.calls)
	}
}

// A Gloas PTC vote goes out as its typed message; without Gloas in the
// chain the policy refuses it before any call.
func TestGloasPayloadAttestation(t *testing.T) {
	ptc := `{"type":"PAYLOAD_ATTESTATION_MESSAGE",` + forkInfo + `,"payload_attestation_message":{"version":"GLOAS","data":` +
		`{"beacon_block_root":"0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464","slot":"13164545","payload_present":true,"blob_data_available":false}}}`
	srv, f := newTestServer(t)
	code, _, body := post(t, srv, pubHex, "application/json", ptc)
	if code != 412 || len(f.calls) != 0 {
		t.Fatalf("no Gloas in the chain: %d %s, calls %v", code, body, f.calls)
	}

	ts, f := gloasServer(t)
	code, _, body = post(t, ts, pubHex, "application/json", ptc)
	if code != 200 || len(f.calls) != 1 || f.calls[0] != "payload_attestation" || [4]byte(f.domain[:4]) != eth2.DomainPTCAttester {
		t.Fatalf("%d %s, calls %v, domain %#x", code, body, f.calls, f.domain)
	}
}

// Grandine 3.0.0-rc.1 sends type PAYLOAD_ATTESTATION with the bare data
// under payload_attestation and reads the reply as JSON {"signature"}
// (reqwest sends Accept: */*).
func TestGrandinePayloadAttestation(t *testing.T) {
	ptc := `{"type":"PAYLOAD_ATTESTATION",` + forkInfo + `,"payload_attestation":` +
		`{"beacon_block_root":"0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464","slot":"13164545","payload_present":true,"blob_data_available":false}}`
	ts, f := gloasServer(t)
	code, ct, body := post(t, ts, pubHex, "*/*", ptc)
	var reply struct {
		Signature string `json:"signature"`
	}
	if code != 200 || !strings.HasPrefix(ct, "application/json") || json.Unmarshal([]byte(body), &reply) != nil || len(reply.Signature) != 2+2*96 {
		t.Fatalf("%d %s %s", code, ct, body)
	}
	if len(f.calls) != 1 || f.calls[0] != "payload_attestation" || [4]byte(f.domain[:4]) != eth2.DomainPTCAttester {
		t.Fatalf("calls %v, domain %#x", f.calls, f.domain)
	}
}

// Builder API authentication goes out as its typed message under
// DOMAIN_BUILDER_REQUEST_AUTH, without fork_info.
func TestBuilderRequestAuth(t *testing.T) {
	auth := `{"type":"BUILDER_REQUEST_AUTH","builder_request_auth":{"version":"GLOAS","data":{"data":"0x6275696c6465722e6578616d706c652e6f7267","slot":"32"}}}`
	ts, f := gloasServer(t)
	code, _, body := post(t, ts, pubHex, "application/json", auth)
	if code != 200 || len(f.calls) != 1 || f.calls[0] != "builder_request_auth" || [4]byte(f.domain[:4]) != eth2.DomainBuilderRequestAuth {
		t.Fatalf("%d %s, calls %v, domain %#x", code, body, f.calls, f.domain)
	}
}

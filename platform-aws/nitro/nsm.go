package nitro

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// NSM wraps a session on /dev/nsm. The Nitro hypervisor answers it; the
// parent instance is not on that path.
type NSM struct {
	mu   sync.Mutex
	sess *nsm.Session
}

// OpenNSM opens /dev/nsm. It fails outside a Nitro enclave.
func OpenNSM() (*NSM, error) {
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("nitro: open /dev/nsm: %w", err)
	}
	return &NSM{sess: s}, nil
}

func (n *NSM) Close() error { return n.sess.Close() }

// Document returns a COSE_Sign1 attestation document from the NSM with the
// given nonce, user data and public key (each optional, at most 1024 bytes).
func (n *NSM) Document(nonce, userData, publicKey []byte) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	res, err := n.sess.Send(&request.Attestation{Nonce: nonce, UserData: userData, PublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, fmt.Errorf("nitro: nsm: %s", res.Error)
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("nitro: nsm returned no document")
	}
	return res.Attestation.Document, nil
}

// Attest implements platform.Attester. The client verifies the document
// against the AWS Nitro root (see cloud/aws/README.md).
func (n *NSM) Attest(_ context.Context, nonce, userData []byte) (*backend.Attestation, error) {
	doc, err := n.Document(nonce, userData, nil)
	if err != nil {
		return nil, err
	}
	return attestation(doc, userData), nil
}

// attestation is what the runner sends as the proof of a Nitro identity.
// The debug build's fake NSM (hooks_debug.go) builds the same value.
func attestation(doc, userData []byte) *backend.Attestation {
	return &backend.Attestation{Platform: "nitro", Format: "aws-nitro-cose-sign1", UserData: userData, Document: doc}
}

// AttestationPayload is the part of the document payload the runner reads.
// Field names follow the AWS Nitro Enclaves attestation document spec.
type AttestationPayload struct {
	ModuleID  string         `cbor:"module_id"`
	Digest    string         `cbor:"digest"`
	Timestamp uint64         `cbor:"timestamp"` // ms since the epoch
	PCRs      map[int][]byte `cbor:"pcrs"`
	PublicKey []byte         `cbor:"public_key"`
	UserData  []byte         `cbor:"user_data"`
	Nonce     []byte         `cbor:"nonce"`
}

type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// ParseDocument decodes the payload of a COSE_Sign1 attestation document
// without checking the signature. Use it only on documents read straight
// from /dev/nsm; documents from elsewhere need full verification.
func ParseDocument(doc []byte) (*AttestationPayload, error) {
	var msg coseSign1
	if err := cbor.Unmarshal(doc, &msg); err != nil {
		return nil, fmt.Errorf("nitro: COSE_Sign1: %w", err)
	}
	var p AttestationPayload
	if err := cbor.Unmarshal(msg.Payload, &p); err != nil {
		return nil, fmt.Errorf("nitro: payload: %w", err)
	}
	return &p, nil
}

// documentImage is the allowed_image_measurements entry of a document read
// straight from /dev/nsm (ParseDocument): its PCR0 to PCR2.
func documentImage(doc []byte) (setupwire.Image, error) {
	p, err := ParseDocument(doc)
	if err != nil {
		return setupwire.Image{}, err
	}
	return platform.NitroImage(p.PCRs)
}

// NSMTime is a clock.Source that reads the timestamp of a fresh
// attestation document. Open question for AWS: which clock the hypervisor
// uses for it, and whether the parent can influence it. Trail of Bits
// advises against reasoning about enclave time from it
// (https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/).
// UNTESTED: needs a Nitro enclave.
type NSMTime struct{ NSM *NSM }

func (s NSMTime) Name() string { return "nsm-timestamp" }

func (s NSMTime) Fetch(context.Context) (time.Time, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return time.Time{}, err
	}
	doc, err := s.NSM.Document(nonce, nil, nil)
	if err != nil {
		return time.Time{}, err
	}
	p, err := ParseDocument(doc)
	if err != nil {
		return time.Time{}, err
	}
	if !bytes.Equal(p.Nonce, nonce) {
		return time.Time{}, errors.New("nitro: attestation nonce mismatch")
	}
	return time.UnixMilli(int64(p.Timestamp)), nil
}

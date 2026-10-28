//go:build !peerselect || peer_aws

package runnerclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// What a Nitro runner puts in its attestation (runner/platform/nitro).
const (
	nitroPlatform = "nitro"
	nitroFormat   = "aws-nitro-cose-sign1"
	// maxNitroPCR is the highest PCR index of an NSM document.
	maxNitroPCR = 31
)

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// NitroPCRValues are the expected PCR values of the nitro_pcrs setting,
// checked as the Nitro verifier checks them (PCR0 to PCR2 set, not zero).
func (a *Attestation) NitroPCRValues() (map[int][]byte, error) { return a.nitroPCRs() }

// nitroPCRs turns the nitro_pcrs setting into the expected PCR values.
func (a *Attestation) nitroPCRs() (map[int][]byte, error) {
	if len(a.NitroPCRs) == 0 {
		return nil, errors.New("attestation.nitro_pcrs: not set (the expected PCR0, PCR1 and PCR2 of the enclave image, 96 hex digits each)")
	}
	pcrs := map[int][]byte{}
	for _, k := range sortedKeys(a.NitroPCRs) {
		idx, err := strconv.Atoi(k)
		if err != nil || idx < 0 || idx > maxNitroPCR || strconv.Itoa(idx) != k {
			return nil, fmt.Errorf("attestation.nitro_pcrs: key %q is not a PCR index (0 to %d, plain decimal)", k, maxNitroPCR)
		}
		v, err := hex.DecodeString(strings.ToLower(a.NitroPCRs[k]))
		if err != nil || len(v) != 48 {
			return nil, fmt.Errorf("attestation.nitro_pcrs: pcr%d want 96 hex digits (SHA-384)", idx)
		}
		pcrs[idx] = v
	}
	for i := 0; i <= 2; i++ {
		v, ok := pcrs[i]
		if !ok {
			return nil, fmt.Errorf("attestation.nitro_pcrs: pcr%d not set (PCR0, PCR1 and PCR2 are required)", i)
		}
		if allZero(v) {
			return nil, fmt.Errorf("attestation.nitro_pcrs: pcr%d is all zero, the value of a debug-mode enclave", i)
		}
	}
	return pcrs, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// nitroVerifier returns the aws-nitro verifier for the settings.
func (a *Attestation) nitroVerifier(o *options) (remote.VerifyFunc, error) {
	n, err := a.newNitro(o)
	if err != nil {
		return nil, err
	}
	return n.verify, nil
}

// nitroDocumentVerifier returns the aws-nitro document verifier.
func (a *Attestation) nitroDocumentVerifier(o *options) (DocumentVerifier, error) {
	n, err := a.newNitro(o)
	if err != nil {
		return nil, err
	}
	return n.verifyDocument, nil
}

func (a *Attestation) newNitro(o *options) (*nitroVerifier, error) {
	pcrs, err := a.nitroPCRs()
	if err != nil {
		return nil, err
	}
	if r := strings.ToLower(a.NitroRootSHA256); a.NitroRootSHA256 != "" {
		if b, err := hex.DecodeString(r); err != nil || len(b) != 32 {
			return nil, errors.New("attestation.nitro_root_sha256: want 64 hex digits")
		}
		if r != attest.NitroRootSHA256 {
			return nil, fmt.Errorf("attestation.nitro_root_sha256: this build pins the AWS Nitro root %s, not %s; another root needs a code change", attest.NitroRootSHA256, r)
		}
	}
	return &nitroVerifier{opts: attest.NitroOptions{PCRs: pcrs, Roots: o.nitroRoots}}, nil
}

// nitroVerifier checks the NSM document of an IDENTITY response: it must be
// a Nitro document for this identity and nonce, signed through a chain to
// the pinned AWS root, from a non-debug enclave with the expected PCRs.
type nitroVerifier struct{ opts attest.NitroOptions }

func (n *nitroVerifier) verify(_ context.Context, nonce []byte, id *backend.Identity) error {
	if err := checkDocument(nonce, id, nitroPlatform, nitroFormat, "an AWS Nitro document"); err != nil {
		return err
	}
	// checkDocument compared the user data with the identity fields; the
	// document must carry that user data and the nonce.
	o := n.opts
	o.Nonce, o.UserData = nonce, id.Attestation.UserData
	_, err := attest.VerifyNitro(id.Attestation.Document, o)
	return err
}

// verifyDocument checks an NSM document that carries nonce and userData.
func (n *nitroVerifier) verifyDocument(_ context.Context, nonce, userData []byte, a *backend.Attestation) error {
	if err := checkUserData(userData, a, nitroPlatform, nitroFormat, "an AWS Nitro document"); err != nil {
		return err
	}
	o := n.opts
	o.Nonce, o.UserData = nonce, userData
	_, err := attest.VerifyNitro(a.Document, o)
	return err
}

func init() {
	verifierFactories[VerifierAWSNitro] = (*Attestation).nitroVerifier
	documentFactories[VerifierAWSNitro] = (*Attestation).nitroDocumentVerifier
}

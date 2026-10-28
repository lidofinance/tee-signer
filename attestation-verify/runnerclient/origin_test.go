//go:build !peerselect

package runnerclient

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
	"github.com/lidofinance/tee-signer/tee-signer/handoverorder"
)

// A handover target checks the source's origin proof (handover) the way
// checkOrigin in tee-signer/server/handover_import.go does: the settings of the
// order's source give a document verifier (OrderAttestation,
// NewDocumentVerifier), which checks the page's document against the page's
// nonce and handover.OriginUserData(order hash, origin key). These tests run
// that path with the platform fakes of the identity tests: NSM documents
// from a test CA, MAA and Confidential Space tokens from the fake provider
// of maaEnv. Nothing here ran against a real platform.
//
// What the documents bind. A Nitro document binds the page's nonce and the
// user data. The Azure and GCP attesters (runner/platform/azure and gcp)
// drop the nonce, and their document verifiers ignore it. On those two the
// proof binds the order and the origin key only: a recorded proof passes
// for another request under the same order and key while its token is
// valid, and there is no nonce to test. No document carries a setup hash.
// The source's setup reaches the proof only through the order hash in the
// user data, and that is what TestOriginProofWrongSetup checks.

// originPlatform is a source platform: its cloud.json settings and its
// documents, each for the good image ("") or for one of others.
type originPlatform struct {
	name string
	// others name other images: a document made by one of them, and
	// settings that name it.
	others   []string
	settings func(image string) Attestation
	doc      func(image string, nonce, userData []byte) *backend.Attestation
	opts     []Option
	// bindErr is what the document's own check returns when the document
	// binds other user data than the target expects.
	bindErr    error
	bindsNonce bool
}

// originProject is the gcp-cs source's project. OrderParticipant needs one,
// and the fake token's default "p" is not a valid project ID.
const originProject = "signer-project"

func newOriginPlatform(t *testing.T, name string) *originPlatform {
	t.Helper()
	switch name {
	case VerifierAWSNitro:
		env := newNitroEnv(t)
		pcrs := func(image string) map[uint64][]byte {
			m := testgen.DefaultPCRs()
			switch image {
			case "pcr0": // another enclave image
				m[0] = testgen.PCRValue(0xd0)
			case "pcr3": // the same image under another parent's IAM role
				m[3] = testgen.PCRValue(0xd3)
			}
			return m
		}
		return &originPlatform{
			name: name, others: []string{"pcr0", "pcr3"}, bindErr: attest.ErrUserData, bindsNonce: true,
			opts: []Option{withNitroRoots(env.ca.Root)},
			settings: func(image string) Attestation {
				m := pcrs(image)
				a := Attestation{Verifier: VerifierAWSNitro, NitroPCRs: map[string]string{}}
				for _, i := range []uint64{0, 1, 2, 3, 8} {
					a.NitroPCRs[fmt.Sprint(i)] = hex.EncodeToString(m[i])
				}
				return a
			},
			doc: func(image string, nonce, ud []byte) *backend.Attestation {
				doc := env.ca.NitroDoc(t, testgen.NitroSpec{TS: time.Now(), PCRs: pcrs(image), Nonce: nonce, UserData: ud})
				return &backend.Attestation{Platform: nitroPlatform, Format: nitroFormat, UserData: ud, Document: doc}
			},
		}
	case VerifierAzureMAA:
		env := newMAAEnv(t, mainKeySet(t))
		hostData := func(image string) string {
			if image == "" {
				return goodHostData
			}
			return strings.Repeat("22", 32) // another CCE policy
		}
		// MAA's check of the report data reports a mismatch as ErrNonce.
		return &originPlatform{
			name: name, others: []string{"hostdata"}, bindErr: attest.ErrNonce,
			opts: []Option{WithHTTPClient(env.srv.Client())},
			settings: func(image string) Attestation {
				return Attestation{Verifier: VerifierAzureMAA, MAAHost: env.host, CCEPolicySHA256: hostData(image)}
			},
			doc: func(image string, _, ud []byte) *backend.Attestation {
				tok := env.token(tokenSpec{hostData: hostData(image)}, backend.MAARuntimeData(ud))
				return &backend.Attestation{Platform: "azure", Format: "azure-maa-jwt", UserData: ud, Document: []byte(tok)}
			},
		}
	case VerifierGCPCS:
		env := newMAAEnv(t, mainKeySet(t))
		digest := func(image string) string {
			if image == "" {
				return gcpDigest
			}
			return "sha256:" + strings.Repeat("33", 32) // another container image
		}
		// The user data is the token's eat_nonce, so a mismatch is ErrNonce.
		return &originPlatform{
			name: name, others: []string{"digest"}, bindErr: attest.ErrNonce,
			opts: []Option{WithHTTPClient(env.srv.Client())},
			settings: func(image string) Attestation {
				a := gcpGood(env.issuer)
				a.GCPImageDigest = digest(image)
				a.GCPServiceAccount, a.GCPProjectID = gcpAccount, originProject
				return a
			},
			doc: func(image string, _, ud []byte) *backend.Attestation {
				tok := env.gcpToken(gcpSpec{claims: func(c map[string]any) {
					setPath(c, "submods.container.image_digest", digest(image))
					setPath(c, "submods.gce.project_id", originProject)
				}}, ud)
				return &backend.Attestation{Platform: gcpPlatform, Format: gcpFormat, UserData: ud, Document: []byte(tok)}
			},
		}
	}
	t.Fatalf("no origin platform %q", name)
	return nil
}

// forOriginPlatforms runs f for each cloud platform, with fresh fakes.
func forOriginPlatforms(t *testing.T, f func(t *testing.T, p *originPlatform)) {
	for _, name := range []string{VerifierAWSNitro, VerifierAzureMAA, VerifierGCPCS} {
		t.Run(name, func(t *testing.T) { f(t, newOriginPlatform(t, name)) })
	}
}

// The source's setup, another setup, the order's not_after and the
// request's nonce.
var (
	originSetup = [32]byte{0x51}
	otherSetup  = [32]byte{0x61}
	originNonce = bytes.Repeat([]byte{0x4e}, 32)
)

const originNotAfter = 1_800_000_000

// originOrder drafts a handover order whose source runs with settings a and
// setup, the way an approver's tool does (OrderParticipant). It returns the
// body the target decodes from the order's wire form, and the order hash.
func originOrder(t *testing.T, a Attestation, setup [32]byte, notAfter uint64) (*handoverorder.Body, [32]byte) {
	t.Helper()
	src, err := a.OrderParticipant("signer-2", setup, [32]byte{})
	if err != nil {
		t.Fatalf("source participant: %v", err)
	}
	b := handoverorder.Body{ClusterID: [32]byte{0xc1}, ChainHash: [32]byte{0xc2}, NotAfter: notAfter, Source: src,
		Target: handoverorder.Runner{Name: "signer-2b", SetupHash: [32]byte{0x52}, Verifier: dkgorder.VerifierDev}}
	raw, err := b.Encode()
	if err != nil {
		t.Fatalf("encode order: %v", err)
	}
	back, err := handoverorder.DecodeBody(raw)
	if err != nil {
		t.Fatalf("decode order: %v", err)
	}
	hash, err := back.Hash()
	if err != nil {
		t.Fatalf("order hash: %v", err)
	}
	return back, hash
}

// originKey is a fresh origin key; the source makes one per process.
func originKey(t *testing.T) [32]byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(pub)
}

// proof is the origin proof a source on image sends for key under the order
// hash: a document over the nonce and OriginUserData(hash, key).
func (p *originPlatform) proof(image string, hash, key [32]byte) handover.OriginProof {
	return handover.OriginProof{Key: key, Nonce: originNonce, Attestation: p.doc(image, originNonce, handover.OriginUserData(hash, key))}
}

// check is the target's check of the proof under order b (checkOrigin in
// runner/server/handover_import.go). The proof goes through the wire form
// of a handover page, and the verifier comes from the order's source.
func (p *originPlatform) check(t *testing.T, b *handoverorder.Body, hash [32]byte, proof handover.OriginProof) error {
	t.Helper()
	raw, err := (&handover.Response{Total: 1, Origin: proof, Carry: handover.Carry{Set: handover.KeySet{Total: 1}}}).Encode()
	if err != nil {
		t.Fatalf("encode page: %v", err)
	}
	page, err := handover.DecodeResponse(raw)
	if err != nil {
		t.Fatalf("decode page: %v", err)
	}
	src := b.Source
	a := OrderAttestation(&src)
	verify, err := a.NewDocumentVerifier(p.opts...)
	if err != nil {
		t.Fatalf("the source's settings: %v", err)
	}
	return verify(ctx, page.Origin.Nonce, handover.OriginUserData(hash, page.Origin.Key), page.Origin.Attestation)
}

// wantRefused checks that the target refuses the proof under order b twice:
// as the source sent it, and with the attestation's UserData field set to
// the bytes the target expects. The second must fail in the document's own
// check, since the field binds nothing.
func (p *originPlatform) wantRefused(t *testing.T, what string, b *handoverorder.Body, hash [32]byte, proof handover.OriginProof) {
	t.Helper()
	if err := p.check(t, b, hash, proof); err == nil {
		t.Fatalf("%s: the target accepted it", what)
	}
	a := *proof.Attestation
	a.UserData = handover.OriginUserData(hash, proof.Key)
	proof.Attestation = &a
	if err := p.check(t, b, hash, proof); !errors.Is(err, p.bindErr) {
		t.Fatalf("%s, UserData field set to the expected bytes: got %v, want %v", what, err, p.bindErr)
	}
}

// The source's proof under its own order passes. On Nitro the document
// binds the request's nonce too.
func TestOriginProofPasses(t *testing.T) {
	forOriginPlatforms(t, func(t *testing.T, p *originPlatform) {
		b, hash := originOrder(t, p.settings(""), originSetup, originNotAfter)
		key := originKey(t)
		if err := p.check(t, b, hash, p.proof("", hash, key)); err != nil {
			t.Fatalf("good proof: %v", err)
		}
		if p.bindsNonce {
			proof := p.proof("", hash, key)
			proof.Nonce = bytes.Repeat([]byte{0x6e}, 32)
			if err := p.check(t, b, hash, proof); !errors.Is(err, attest.ErrNonce) {
				t.Fatalf("a proof sent for another nonce: got %v, want %v", err, attest.ErrNonce)
			}
		}
	})
}

// A proof from another image fails under the order, and a good proof fails
// under an order that names another image. Each image passes under the
// order that names it.
func TestOriginProofWrongMeasurement(t *testing.T) {
	forOriginPlatforms(t, func(t *testing.T, p *originPlatform) {
		b, hash := originOrder(t, p.settings(""), originSetup, originNotAfter)
		key := originKey(t)
		for _, image := range p.others {
			if err := p.check(t, b, hash, p.proof(image, hash, key)); !errors.Is(err, attest.ErrMeasurement) {
				t.Fatalf("%s: a document of another image: got %v, want %v", image, err, attest.ErrMeasurement)
			}
			ob, ohash := originOrder(t, p.settings(image), originSetup, originNotAfter)
			if err := p.check(t, ob, ohash, p.proof("", ohash, key)); !errors.Is(err, attest.ErrMeasurement) {
				t.Fatalf("%s: an order that names another image: got %v, want %v", image, err, attest.ErrMeasurement)
			}
			if err := p.check(t, ob, ohash, p.proof(image, ohash, key)); err != nil {
				t.Fatalf("%s: the other image under the order that names it: %v", image, err)
			}
		}
	})
}

// A proof made under the order for one source setup fails under the order
// for another: the setup is in the order hash, and so in the user data.
func TestOriginProofWrongSetup(t *testing.T) {
	forOriginPlatforms(t, func(t *testing.T, p *originPlatform) {
		b, hash := originOrder(t, p.settings(""), originSetup, originNotAfter)
		ob, ohash := originOrder(t, p.settings(""), otherSetup, originNotAfter)
		if hash == ohash {
			t.Fatal("the source's setup does not change the order hash")
		}
		key := originKey(t)
		good, other := p.proof("", hash, key), p.proof("", ohash, key)
		if err := p.check(t, ob, ohash, other); err != nil {
			t.Fatalf("the other setup's proof under its own order: %v", err)
		}
		p.wantRefused(t, "the proof under the order for another source setup", ob, ohash, good)
		p.wantRefused(t, "a proof made under the order for another source setup", b, hash, other)
	})
}

// The document must bind the origin key and the order hash that the target
// computes the user data from.
func TestOriginProofWrongUserData(t *testing.T) {
	forOriginPlatforms(t, func(t *testing.T, p *originPlatform) {
		b, hash := originOrder(t, p.settings(""), originSetup, originNotAfter)
		_, later := originOrder(t, p.settings(""), originSetup, originNotAfter+1)
		key, otherKey := originKey(t), originKey(t)

		proof := p.proof("", hash, otherKey)
		proof.Key = key
		p.wantRefused(t, "a document over another origin key's user data", b, hash, proof)

		// Someone who holds the source's proof sends it with an origin key
		// of their own.
		proof = p.proof("", hash, key)
		proof.Key = otherKey
		p.wantRefused(t, "a page that names another origin key than its document", b, hash, proof)

		p.wantRefused(t, "a document over another order hash (another not_after)", b, hash, p.proof("", later, key))
	})
}

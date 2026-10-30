package setupwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

const eth = 1_000_000_000

func must32(k [32]byte) []byte { return k[:] }

// approverKey is test approver i: a key from a fixed seed, so signatures
// are the same on every run.
func approverKey(i byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, 32))
}

func approverPub(i byte) [32]byte { return [32]byte(approverKey(i).Public().(ed25519.PublicKey)) }

// makeCA makes a self-signed certificate. isCA false makes a leaf.
func makeCA(t testing.TB, seed byte, cn string, isCA bool) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(seed)),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(2_000_000_000, 0),
		IsCA:         isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// goldenCA is the client CA of the golden setups, kept in testdata so a
// change in Go's certificate encoding cannot change the vectors.
func goldenCA(t testing.TB) []byte {
	t.Helper()
	path := filepath.Join("testdata", "client-ca.der")
	der, err := os.ReadFile(path)
	if err == nil {
		return der
	}
	if !*update {
		t.Fatalf("%v (run with -update to make it)", err)
	}
	der = makeCA(t, 0xca, "signer test client CA", true)
	if err := os.WriteFile(path, der, 0o644); err != nil {
		t.Fatal(err)
	}
	return der
}

func u64p(v uint64) *uint64 { return &v }

func credentials(prefix, addr byte) backend.Root {
	var wc backend.Root
	wc[0] = prefix
	for i := 12; i < 32; i++ {
		wc[i] = addr
	}
	return wc
}

func sampleLocked() Locked {
	return Locked{
		Approvers:          ApproverSet{Keys: [][32]byte{approverPub(1), approverPub(2), approverPub(3)}, ApprovalsNeeded: 2},
		ChangeDelaySeconds: u64p(0),
		AllowedImageMeasurements: []Image{
			{Kind: ImageNitro, Measurement: bytes.Repeat([]byte{0x11}, 144)},
			{Kind: ImageAzure, Measurement: bytes.Repeat([]byte{0xaa}, 32)},
		},
		AllowedFeeRecipients:                []backend.Address{{0x43}, {0x44}},
		BuilderGasLimitMin:                  30_000_000,
		BuilderGasLimitMax:                  60_000_000,
		BuilderRegistrationMaxFutureSeconds: 3600,
		ExitAllowedValidators:               []uint64{5, 126},
		ExitStakeCapPerDay:                  4096 * eth,
		ExitApprovalsNeeded:                 2,
		MinActivationBalance:                32 * eth,
		MaxEffectiveBalance:                 2048 * eth,
		WithdrawalCredentials:               credentials(0x02, 0x42),
		AllowedDepositAmounts:               []uint64{eth / 2, 32 * eth},
		BareRootDomains:                     1<<2 | 1<<6,
		AllowedBuilderRequestAuthDataRoots:  []backend.Root{{0x51}, {0x52}},
	}
}

func sampleOpen() Open {
	return Open{
		ForkSchedule: []Fork{
			{Epoch: 0, Version: backend.Version{0x01, 0, 0, 0x10}},
			{Epoch: 10, Version: backend.Version{0x02, 0, 0, 0x10}},
			{Epoch: 20, Version: backend.Version{0x03, 0, 0, 0x10}},
		},
		GloasForkEpoch: u64p(20),
	}
}

func sampleChain() Chain {
	return Chain{
		GenesisValidatorsRoot:    backend.Root{0x4b, 0x36},
		GenesisForkVersion:       backend.Version{0, 0, 0, 0x10},
		GenesisTime:              1_760_000_000,
		SecondsPerSlot:           6,
		SlotsPerEpoch:            8,
		Preset:                   PresetMinimal,
		VoluntaryExitForkVersion: backend.Version{0x04, 0, 0, 0x10},
	}
}

// testSalts are n salts from a fixed tag, so the vectors are the same on
// every run.
func testSalts(tag string, n int) Salts {
	out := make(Salts, n)
	for i := range out {
		out[i] = sha256.Sum256(fmt.Appendf(nil, "test salt %s %d", tag, i))
	}
	return out
}

func testPolicySalts() PolicySalts {
	return PolicySalts{Public: testSalts("public", NumPublicLeaves), Locked: testSalts("locked", NumLockedLeaves),
		Open: testSalts("open", NumOpenLeaves)}
}

// samples are one setup per platform, with every optional part used
// somewhere.
func samples(t testing.TB) map[string]*Setup {
	t.Helper()
	ca := goldenCA(t)
	base := func(name string, id byte, maxKeys, lockDays uint32, p PlatformConfig) *Setup {
		p.AllowedClientCA = [][]byte{ca}
		return &Setup{ClusterID: [32]byte{id, 0xc1}, HandoverGeneration: 1, Chain: sampleChain(),
			Safety: Safety{MaxSignEpochsAheadOfClock: 2,
				SlashingMarkPrewrite: SlashingMarkPrewrite{BlockSlots: 16, SourceEpochs: 2, TargetEpochs: 2}},
			MaxKeys: maxKeys, SlashingLogMinLockDays: lockDays,
			Locked: sampleLocked(), Open: sampleOpen(), PolicySalts: testPolicySalts(),
			SignerName: name, Platform: p, PlatformSalt: sha256.Sum256([]byte("test platform salt " + name))}
	}
	nitro := base("signer-1", 1, 1024, 3650, PlatformConfig{Platform: PlatformNitro,
		SlashingLogStore:  Store{Bucket: "signer-marks", Region: "eu-west-1"},
		SealingKeyRelease: KeyRelease{Region: "eu-west-1", KMSKeyID: "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"}})
	nitro.Locked.ChangeDelaySeconds = nil
	azStore := func() Store {
		return Store{Account: "signermarks", Container: "marks", Subscription: "0b2c3d4e-5f60-4718-9a2b-3c4d5e6f7a8b", ResourceGroup: "signer-rg"}
	}
	azState := azStore()
	azure := base("signer-2", 1, 8192, 30, PlatformConfig{Platform: PlatformAzure,
		SlashingLogStore:    azStore(),
		EncryptedStateStore: &azState,
		SealingKeyRelease:   KeyRelease{MAAEndpoint: "sharedeus.eus.attest.azure.net", AKVEndpoint: "signer-kv.vault.azure.net", KID: "signer-key"}})
	azure.Open.GloasForkEpoch = nil
	// Two slot time changes: 4 s slots from epoch 100000, 3 s from 200000.
	azure.Locked.SlotTimeChanges = []SlotTimeChange{{Epoch: 100_000, SecondsPerSlot: 4}, {Epoch: 200_000, SecondsPerSlot: 3}}
	gcp := base("signer-3", 1, 64, 1, PlatformConfig{Platform: PlatformGCP,
		SlashingLogStore:    Store{Bucket: "signer-marks-gcp"},
		EncryptedStateStore: &Store{Bucket: "signer-state_gcp"},
		SealingKeyRelease: KeyRelease{WIFProvider: "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/signer/providers/attest",
			KMSKey: "projects/p/locations/global/keyRings/signer/cryptoKeys/seal", AttestAudience: "signer-runner-identity"}})
	gcp.Locked.AllowedImageMeasurements = nil
	gcp.Locked.AllowedFeeRecipients = nil
	gcp.Locked.ExitAllowedValidators = nil
	gcp.Locked.AllowedDepositAmounts = nil
	gcp.Locked.BareRootDomains = 0
	gcp.Locked.AllowedBuilderRequestAuthDataRoots = nil
	gcp.Locked.AllowUnverifiedNonslashableSigning = true
	gcp.Open = Open{}
	// dev: local directories, no key release, no change delay (as on a
	// devnet).
	dev := base("signer-dev", 4, 16, 7, PlatformConfig{Platform: PlatformDev,
		SlashingLogStore:    Store{Dir: "/var/lib/signer/marks"},
		EncryptedStateStore: &Store{Dir: "/var/lib/signer/state-copy"}})
	dev.Locked.ChangeDelaySeconds = u64p(0)
	// nitro-peers: the Nitro signer of a cluster with an Azure peer
	// (sharedneu) and a GCP peer.
	nitroPeers := base("signer-1", 1, 1024, 3650, nitro.Platform)
	nitroPeers.Locked.ChangeDelaySeconds = nil
	nitroPeers.Platform.PeerAttestationHosts = []string{"confidentialcomputing.googleapis.com:443", "sharedneu.neu.attest.azure.net:443",
		"www.googleapis.com:443"}
	return map[string]*Setup{"setup-nitro": nitro, "setup-azure": azure, "setup-gcp": gcp, "setup-dev": dev, "setup-nitro-peers": nitroPeers}
}

// rawSetup encodes s without the checks, to feed the decoder values the
// encoder refuses.
func rawSetup(s *Setup) []byte {
	w := &writer{}
	s.write(w)
	return w.b
}

// signedUpdate makes a body for the setup's cluster and chain, with test
// salts unless it has salts, and signs it with the given approvers
// (positions in the setup's set) and, for a rotation, with every new key.
func signedUpdate(t testing.TB, s *Setup, body UpdateBody, signers []byte, newKeys []byte) *Update {
	t.Helper()
	body.ClusterID = s.ClusterID
	body.ChainHash = s.Chain.Hash()
	if body.Salts == nil {
		body.Salts = testSalts(fmt.Sprintf("update %s %d", body.Group, body.Version), body.leafCount())
	}
	u := &Update{Body: body}
	sign := func(i byte) [64]byte {
		sig, err := body.Sign(approverKey(i))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	for _, i := range signers {
		u.Approvals = append(u.Approvals, Approval{Position: i, Signature: sign(i + 1)})
	}
	for pos, i := range newKeys {
		u.NewSet = append(u.NewSet, Approval{Position: uint8(pos), Signature: sign(i)})
	}
	return u
}

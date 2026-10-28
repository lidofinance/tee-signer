package setupwire

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The golden vectors of the attestation statement
// (docs/attestation-statement.md and docs/attestation-statement-vectors.json
// in the cloud repo): a sample GCP setup, its leaves and roots,
// platform_commitment and setup_hash, a config update, a SetupState, and
// the ATTEST user data with the GCP eat_nonce; an Azure signer of the same
// cluster with its user data, MAA runtime data and report data; a Nitro
// signer of the same cluster with its user data; and the measurement
// output for a sample value of each platform. The circuits and
// the watchdog are written against them. go test -run TestStatementVectors
// -update rewrites the file.

const vectorsPath = "../../attestation-verify/docs/attestation-statement-vectors.json"

func vsum(tag string) [32]byte { return sha256.Sum256([]byte("statement vector " + tag)) }

func vsalts(tag string, n int) Salts {
	out := make(Salts, n)
	for i := range out {
		out[i] = vsum(fmt.Sprintf("%s salt %d", tag, i))
	}
	return out
}

// statementSetup is the sample: a GCP signer of a Hoodi cluster with one
// slot time change (6 s slots from epoch 200000).
func statementSetup(t testing.TB) *Setup {
	t.Helper()
	root := func(s string) backend.Root { return backend.Root(must(hex.DecodeString(s))) }
	ver := func(s string) backend.Version { return backend.Version(must(hex.DecodeString(s))) }
	gloas := uint64(132352)
	delay := uint64(172800)
	digest := vsum("gcp image digest")
	s := &Setup{
		ClusterID:          vsum("cluster_id"),
		HandoverGeneration: 1,
		Chain: Chain{GenesisValidatorsRoot: root("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"),
			GenesisForkVersion: ver("10000910"), GenesisTime: 1742213400, SecondsPerSlot: 12, SlotsPerEpoch: 32,
			Preset: PresetMainnet, VoluntaryExitForkVersion: ver("40000910")},
		Safety:                 Safety{MaxSignEpochsAheadOfClock: 2, SlashingMarkPrewrite: SlashingMarkPrewrite{BlockSlots: 32, SourceEpochs: 2, TargetEpochs: 2}},
		MaxKeys:                1024,
		SlashingLogMinLockDays: 3650,
		Locked: Locked{
			Approvers:                           ApproverSet{Keys: [][32]byte{approverPub(1), approverPub(2), approverPub(3)}, ApprovalsNeeded: 2},
			ChangeDelaySeconds:                  &delay,
			AllowedImageMeasurements:            []Image{{Kind: ImageGCP, Measurement: digest[:]}},
			AllowedFeeRecipients:                []backend.Address{backend.Address(must(hex.DecodeString("000000000000000000000000000000000000dead")))},
			BuilderGasLimitMin:                  30_000_000,
			BuilderGasLimitMax:                  200_000_000,
			BuilderRegistrationMaxFutureSeconds: 3600,
			ExitAllowedValidators:               []uint64{1234, 5678},
			ExitStakeCapPerDay:                  1024 * eth,
			ExitApprovalsNeeded:                 2,
			MinActivationBalance:                32 * eth,
			MaxEffectiveBalance:                 2048 * eth,
			WithdrawalCredentials:               credentials(0x01, 0x42),
			AllowedDepositAmounts:               []uint64{32 * eth},
			BareRootDomains:                     1 << 2,
			SlotTimeChanges:                     []SlotTimeChange{{Epoch: 200000, SecondsPerSlot: 6}},
		},
		Open: Open{ForkSchedule: []Fork{{0, ver("50000910")}, {2048, ver("60000910")}, {50688, ver("70000910")}, {132352, ver("80000910")}},
			GloasForkEpoch: &gloas},
		PolicySalts: PolicySalts{Public: vsalts("public", NumPublicLeaves), Locked: vsalts("locked", NumLockedLeaves), Open: vsalts("open", NumOpenLeaves)},
		SignerName:  "gcp-1",
		Platform: PlatformConfig{Platform: PlatformGCP, AllowedClientCA: [][]byte{goldenCA(t)},
			SlashingLogStore:    Store{Bucket: "lido-signer-marks-gcp-1"},
			EncryptedStateStore: &Store{Bucket: "lido-signer-state-gcp-1"},
			SealingKeyRelease: KeyRelease{WIFProvider: "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/signer/providers/attest",
				KMSKey: "projects/signer/locations/global/keyRings/signer/cryptoKeys/seal-gcp-1", AttestAudience: "signer-runner-identity"}},
		PlatformSalt: vsum("platform_salt gcp-1"),
	}
	if _, err := s.Encode(); err != nil {
		t.Fatal(err)
	}
	return s
}

// statementNitroSetup is the third sample: a Nitro signer of the same
// cluster, the same public values and policy salts as the GCP sample, its
// own private part.
func statementNitroSetup(t testing.TB) *Setup {
	t.Helper()
	s := statementSetup(t)
	s.SignerName = "nitro-1"
	s.Platform = PlatformConfig{Platform: PlatformNitro, AllowedClientCA: s.Platform.AllowedClientCA,
		SlashingLogStore:           Store{Bucket: "lido-signer-marks-nitro-1", Region: "eu-central-1"},
		SealingKeyRelease:          KeyRelease{Region: "eu-central-1", KMSKeyID: "arn:aws:kms:eu-central-1:111122223333:key/0b6f4c7e-58a1-4c39-9d2e-5f0a8e3b7c41"},
		KeygenPeerAttestationHosts: []string{"signer-2.example.internal:9443"}}
	s.PlatformSalt = vsum("platform_salt nitro-1")
	if _, err := s.Encode(); err != nil {
		t.Fatal(err)
	}
	return s
}

// statementAzureSetup is the second sample: an Azure signer of the same
// cluster. Its public values and policy salts are the GCP sample's, so it
// has the same policy_root; its private part is Azure's.
func statementAzureSetup(t testing.TB) *Setup {
	t.Helper()
	s := statementSetup(t)
	s.SignerName = "azure-1"
	s.Platform = PlatformConfig{Platform: PlatformAzure, AllowedClientCA: s.Platform.AllowedClientCA,
		SlashingLogStore: Store{Account: "lidosignermarks", Container: "marks-azure-1",
			Subscription: "0b6f4c7e-58a1-4c39-9d2e-5f0a8e3b7c41", ResourceGroup: "signer-azure-1"},
		EncryptedStateStore: &Store{Account: "lidosignerstate", Container: "state-azure-1",
			Subscription: "0b6f4c7e-58a1-4c39-9d2e-5f0a8e3b7c41", ResourceGroup: "signer-azure-1"},
		SealingKeyRelease: KeyRelease{MAAEndpoint: "sharedneu.neu.attest.azure.net",
			AKVEndpoint: "signer-poc-kv.vault.azure.net", KID: "signer-kek-1/0123456789abcdef0123456789abcdef"}}
	s.PlatformSalt = vsum("platform_salt azure-1")
	if _, err := s.Encode(); err != nil {
		t.Fatal(err)
	}
	return s
}

// measurementContext is the context of the circuits' measurement output.
// The runner never hashes it, so it is not in the registry (contexts.go).
const measurementContext = "signer-measurement-v1"

type vMeasurement struct {
	Platform uint8    `json:"platform"`
	Value    hexBytes `json:"value"`
	Input    hexBytes `json:"input"`
	Hash     hexBytes `json:"measurement"`
}

// measurementVector is the measurement output for value on platform:
// H("signer-measurement-v1", platform:u8 || value), with its input.
func measurementVector(platform uint8, value []byte) vMeasurement {
	in := slices.Concat(binary.BigEndian.AppendUint16(nil, uint16(len(measurementContext))), []byte(measurementContext), []byte{platform}, value)
	h := sha256.Sum256(in)
	return vMeasurement{Platform: platform, Value: value, Input: in, Hash: h[:]}
}

type hexBytes []byte

func (h hexBytes) MarshalText() ([]byte, error) { return []byte("0x" + hex.EncodeToString(h)), nil }

type vLeaf struct {
	Index int      `json:"index"`
	Name  string   `json:"name"`
	Value hexBytes `json:"value"`
	Salt  hexBytes `json:"salt"`
	Hash  hexBytes `json:"hash"`
}

// vGroups holds one value per group, in leaf-tree order.
type vGroups[T any] struct {
	Public T `json:"public"`
	Locked T `json:"locked"`
	Open   T `json:"open"`
}

type vKey struct {
	Pubkey      backend.Pubkey `json:"pubkey"`
	SharePubkey backend.Pubkey `json:"share_pubkey"`
}

type vectors struct {
	Description string            `json:"description"`
	Contexts    map[string]string `json:"contexts"`
	Setup       struct {
		Human              string            `json:"human"`
		Bytes              hexBytes          `json:"bytes"`
		Leaves             vGroups[[]vLeaf]  `json:"leaves"`
		Roots              vGroups[hexBytes] `json:"group_roots"`
		PolicyRoot         hexBytes          `json:"policy_root"`
		PlatformSalt       hexBytes          `json:"platform_salt"`
		PrivatePart        hexBytes          `json:"private_part"`
		PlatformCommitment hexBytes          `json:"platform_commitment"`
		SetupHash          hexBytes          `json:"setup_hash"`
	} `json:"setup"`
	Update struct {
		Human      string   `json:"human"`
		Body       hexBytes `json:"body"`
		GroupRoot  hexBytes `json:"group_root"`
		Header     hexBytes `json:"header"`
		UpdateHash hexBytes `json:"update_hash"`
		Signed     hexBytes `json:"signed"`
	} `json:"update"`
	SetupState struct {
		Fields backend.SetupState `json:"fields"`
		Bytes  hexBytes           `json:"bytes"`
	} `json:"setup_state"`
	Attest struct {
		Nonce            hexBytes `json:"nonce"`
		Keys             []vKey   `json:"keys"`
		KeysHash         hexBytes `json:"keys_hash"`
		UserDataInput    hexBytes `json:"user_data_input"`
		UserData         hexBytes `json:"user_data"`
		GCPEatNonce      string   `json:"gcp_eat_nonce"`
		AzureRuntimeData string   `json:"azure_runtime_data"`
		AzureReportData  hexBytes `json:"azure_report_data"`
		NitroNonce       hexBytes `json:"nitro_nonce"`
		NitroUserData    hexBytes `json:"nitro_user_data"`
	} `json:"attest"`
	// PublicOutputs are the statement's public outputs that come from the
	// signer (docs/attestation-statement.md, section 5): config_state is
	// bytes 32 to 312 of the setup state (both groups, the approver set
	// hash, the pending order, key_release_hash), key_origin bytes 313 to
	// 352. PrivateInputs is what the statement keeps private.
	PublicOutputs struct {
		ChallengeRoot      hexBytes `json:"challenge_root"`
		PolicyRoot         hexBytes `json:"policy_root"`
		PlatformCommitment hexBytes `json:"platform_commitment"`
		ConfigState        hexBytes `json:"config_state"`
		KeyOrigin          hexBytes `json:"key_origin"`
	} `json:"public_outputs"`
	PrivateInputs struct {
		KeysHash hexBytes `json:"keys_hash"`
	} `json:"private_inputs"`
	// AzureSetup is an Azure signer of the same cluster (the same public
	// values and salts, so the same policy_root), AzureAttest its ATTEST
	// user data for the same nonce, setup state (with its own setup_hash)
	// and keys, with the MAA runtime data and SNP report data, and
	// AzurePublicOutputs its outputs as public_outputs has the GCP ones.
	AzureSetup struct {
		Human              string   `json:"human"`
		Bytes              hexBytes `json:"bytes"`
		PolicyRoot         hexBytes `json:"policy_root"`
		PlatformSalt       hexBytes `json:"platform_salt"`
		PrivatePart        hexBytes `json:"private_part"`
		PlatformCommitment hexBytes `json:"platform_commitment"`
		SetupHash          hexBytes `json:"setup_hash"`
	} `json:"azure_setup"`
	AzureAttest struct {
		UserDataInput hexBytes `json:"user_data_input"`
		UserData      hexBytes `json:"user_data"`
		RuntimeData   string   `json:"runtime_data"`
		ReportData    hexBytes `json:"report_data"`
	} `json:"azure_attest"`
	AzurePublicOutputs struct {
		ChallengeRoot      hexBytes `json:"challenge_root"`
		PolicyRoot         hexBytes `json:"policy_root"`
		PlatformCommitment hexBytes `json:"platform_commitment"`
		ConfigState        hexBytes `json:"config_state"`
		KeyOrigin          hexBytes `json:"key_origin"`
	} `json:"azure_public_outputs"`
	// NitroSetup is a Nitro signer of the same cluster, NitroAttest its
	// ATTEST user data (the NSM document's user_data, with nonce = the
	// challenge root), NitroPublicOutputs its outputs.
	NitroSetup struct {
		Human              string   `json:"human"`
		Bytes              hexBytes `json:"bytes"`
		PolicyRoot         hexBytes `json:"policy_root"`
		PlatformSalt       hexBytes `json:"platform_salt"`
		PrivatePart        hexBytes `json:"private_part"`
		PlatformCommitment hexBytes `json:"platform_commitment"`
		SetupHash          hexBytes `json:"setup_hash"`
	} `json:"nitro_setup"`
	NitroAttest struct {
		UserDataInput hexBytes `json:"user_data_input"`
		UserData      hexBytes `json:"user_data"`
	} `json:"nitro_attest"`
	NitroPublicOutputs struct {
		ChallengeRoot      hexBytes `json:"challenge_root"`
		PolicyRoot         hexBytes `json:"policy_root"`
		PlatformCommitment hexBytes `json:"platform_commitment"`
		ConfigState        hexBytes `json:"config_state"`
		KeyOrigin          hexBytes `json:"key_origin"`
	} `json:"nitro_public_outputs"`
	// Measurement is the public measurement output (section 5) for the
	// sample setup's GCP image, a sample CCE policy hash and sample PCRs.
	Measurement struct {
		Nitro vMeasurement `json:"nitro"`
		Azure vMeasurement `json:"azure"`
		GCP   vMeasurement `json:"gcp"`
	} `json:"measurement"`
	// KeygenOrders is a worked example of keygen_orders_hash (section 5):
	// the order hashes of a runner's generated keys, one per key, in no
	// order and with repeats, and the hash over the distinct ones. The
	// sample setup state above keeps its placeholder orders_hash.
	KeygenOrders struct {
		KeyOrders []hexBytes `json:"key_orders"`
		Input     hexBytes   `json:"input"`
		Hash      hexBytes   `json:"keygen_orders_hash"`
	} `json:"keygen_orders"`
	// KeyRelease works key_release_hash (section 5) through for a sample
	// AWS key and a sample Azure key: the fields the runner reads, in
	// order, the input and the hash.
	KeyRelease struct {
		Nitro vKeyRelease `json:"nitro"`
		Azure vKeyRelease `json:"azure"`
	} `json:"key_release"`
}

type vKeyRelease struct {
	Platform uint8    `json:"platform"`
	Fields   []vField `json:"fields"`
	Input    hexBytes `json:"input"`
	Hash     hexBytes `json:"key_release_hash"`
}

type vField struct {
	Name  string   `json:"name"`
	Value hexBytes `json:"value"`
}

// keyReleaseVector is the vector of platform's fields, given as name and
// value pairs.
func keyReleaseVector(platform uint8, pairs ...string) vKeyRelease {
	v := vKeyRelease{Platform: platform}
	var vals [][]byte
	in := append(CtxKeyRelease.Message(), platform)
	for i := 0; i+1 < len(pairs); i += 2 {
		val := []byte(pairs[i+1])
		v.Fields = append(v.Fields, vField{pairs[i], val})
		vals = append(vals, val)
		in = binary.BigEndian.AppendUint32(in, uint32(len(val)))
		in = append(in, val...)
	}
	h := backend.KeyReleaseHash(platform, vals...)
	v.Input, v.Hash = in, h[:]
	return v
}

func buildVectors(t *testing.T) []byte {
	s := statementSetup(t)
	var v vectors
	v.Description = "Golden vectors of the attestation statement, setup format 1 (docs/attestation-statement.md). " +
		"Hex is 0x-prefixed; every hash is SHA-256. Made by backend/setupwire TestStatementVectors -update; the test recomputes them."
	v.Contexts = map[string]string{}
	for _, c := range []struct {
		key string
		ctx Context
	}{
		{"policy_leaf", CtxPolicyLeaf}, {"policy_node", CtxPolicyNode}, {"policy_root", CtxPolicyRoot},
		{"platform_commitment", CtxPlatformCommitment}, {"setup_hash", CtxSetup}, {"config_update", CtxConfigUpdate},
		{"chain_hash", CtxChain}, {"approver_set", CtxApproverSet}, {"attest_user_data", CtxRunnerAttest},
		{"identity_user_data", CtxRunnerIdentity}, {"keygen_orders", CtxKeygenOrders}, {"key_release", CtxKeyRelease},
	} {
		v.Contexts[c.key] = c.ctx.String()
	}

	v.Setup.Human = string(must(s.Format()))
	v.Setup.Bytes = must(s.Encode())
	pub := must1(s.PublicLeaves())
	lk := must1(s.Locked.Leaves(s.PolicySalts.Locked))
	op := must1(s.Open.Leaves(s.PolicySalts.Open))
	for _, g := range []struct {
		ls     []Leaf
		leaves *[]vLeaf
		root   *hexBytes
	}{{pub, &v.Setup.Leaves.Public, &v.Setup.Roots.Public}, {lk, &v.Setup.Leaves.Locked, &v.Setup.Roots.Locked}, {op, &v.Setup.Leaves.Open, &v.Setup.Roots.Open}} {
		for i, l := range g.ls {
			h := l.Hash()
			*g.leaves = append(*g.leaves, vLeaf{i, l.Name, l.Value, l.Salt[:], h[:]})
		}
		r := GroupRoot(g.ls)
		*g.root = r[:]
	}
	pr := must1(s.PolicyRoot())
	pc := must1(s.PlatformCommitment())
	sh := must1(s.Hash())
	v.Setup.PolicyRoot, v.Setup.PlatformSalt, v.Setup.PrivatePart = pr[:], s.PlatformSalt[:], must(s.PrivateBytes())
	v.Setup.PlatformCommitment, v.Setup.SetupHash = pc[:], sh[:]

	// Update: locked version 1, builder_gas_limit_max to 300M, signed by
	// approvers 1 and 2.
	l := s.Locked
	l.BuilderGasLimitMax = 300_000_000
	body := UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: GroupLocked, Version: 1,
		PrevHash: must1(s.GroupHash(GroupLocked)), ActivateAt: 1_800_000_000, Locked: &l, Salts: vsalts("update locked 1", NumLockedLeaves)}
	u := &Update{Body: body}
	for _, i := range []byte{0, 1} {
		u.Approvals = append(u.Approvals, Approval{Position: i, Signature: must1(body.Sign(approverKey(i + 1)))})
	}
	if err := u.Verify(&s.Locked.Approvers); err != nil {
		t.Fatal(err)
	}
	gr := must1(body.GroupRoot())
	uh := must1(body.Hash())
	v.Update.Human = string(must(u.Format()))
	v.Update.Body, v.Update.GroupRoot, v.Update.Header = must(body.Encode()), gr[:], must(body.Header())
	v.Update.UpdateHash, v.Update.Signed = uh[:], must(u.Encode())

	// SetupState: locked version 1 in force, the open group at version
	// 0 with an open update pending, a pending DKG order, a key-release
	// hash, and a key origin of 3 keys from key generation. The order and
	// the key-release hash are phase 2; the sample sets them so every
	// public byte is exercised.
	or := must1(s.GroupHash(GroupOpen))
	st := backend.SetupState{
		SetupHash: sh,
		Locked:    backend.ConfigGroup{Version: 1, Hash: uh},
		Open: backend.ConfigGroup{Version: 0, Hash: or,
			Pending: backend.PendingUpdate{Version: 1, Hash: vsum("pending open update"), EffectiveAt: 1_800_000_600}},
		ApproverSetHash: s.Locked.Approvers.Hash(),
		Order:           backend.Order{Kind: 2, Hash: vsum("pending dkg order"), ActAt: 1_800_003_600},
		KeyReleaseHash:  vsum("key release policies"),
		KeyOrigin:       backend.KeyOrigin{Generated: 3, Imported: 0, OrdersHash: vsum("keygen orders")},
	}
	ssb := backend.AppendSetupState(nil, &st)
	v.SetupState.Fields, v.SetupState.Bytes = st, ssb

	// ATTEST: the prover's nonce is a beacon block root.
	nonce := vsum("beacon block root")
	keys := []backend.ValidatorKey{
		{Pubkey: backend.Pubkey(bytes.Repeat([]byte{0xb2}, 48)), SharePubkey: backend.Pubkey(bytes.Repeat([]byte{0xc2}, 48))},
		{Pubkey: backend.Pubkey(bytes.Repeat([]byte{0xa1}, 48)), SharePubkey: backend.Pubkey(bytes.Repeat([]byte{0xc1}, 48))},
	}
	kh := backend.KeysHash(keys)
	ud := backend.AttestUserData(nonce[:], &st, kh)
	in := binary.BigEndian.AppendUint16(nil, uint16(len(backend.AttestContext)))
	in = append(in, backend.AttestContext...)
	in = binary.BigEndian.AppendUint16(in, uint16(len(nonce)))
	in = append(in, nonce[:]...)
	in = append(in, backend.AppendSetupState(nil, &st)...)
	in = append(in, kh[:]...)
	rt := backend.MAARuntimeData(ud)
	rd := make([]byte, 64)
	rs := sha256.Sum256(rt)
	copy(rd, rs[:])
	v.Attest.Nonce = nonce[:]
	for _, k := range keys {
		v.Attest.Keys = append(v.Attest.Keys, vKey{k.Pubkey, k.SharePubkey})
	}
	v.Attest.KeysHash, v.Attest.UserDataInput, v.Attest.UserData = kh[:], in, ud
	v.Attest.GCPEatNonce = hex.EncodeToString(ud)
	v.Attest.AzureRuntimeData, v.Attest.AzureReportData = string(rt), rd
	v.Attest.NitroNonce, v.Attest.NitroUserData = nonce[:], ud

	po := &v.PublicOutputs
	po.ChallengeRoot, po.PolicyRoot, po.PlatformCommitment = nonce[:], pr[:], pc[:]
	po.ConfigState, po.KeyOrigin = ssb[32:313], ssb[313:353]
	v.PrivateInputs.KeysHash = kh[:]

	// The Azure signer: the same setup state but its own setup_hash.
	az := statementAzureSetup(t)
	azpr, azpc, azsh := must1(az.PolicyRoot()), must1(az.PlatformCommitment()), must1(az.Hash())
	if azpr != pr {
		t.Fatal("the Azure sample has another policy_root")
	}
	v.AzureSetup.Human, v.AzureSetup.Bytes = string(must(az.Format())), must(az.Encode())
	v.AzureSetup.PolicyRoot, v.AzureSetup.PlatformSalt, v.AzureSetup.PrivatePart = azpr[:], az.PlatformSalt[:], must(az.PrivateBytes())
	v.AzureSetup.PlatformCommitment, v.AzureSetup.SetupHash = azpc[:], azsh[:]
	azst := st
	azst.SetupHash = azsh
	azssb := backend.AppendSetupState(nil, &azst)
	azud := backend.AttestUserData(nonce[:], &azst, kh)
	azin := binary.BigEndian.AppendUint16(nil, uint16(len(backend.AttestContext)))
	azin = append(azin, backend.AttestContext...)
	azin = binary.BigEndian.AppendUint16(azin, uint16(len(nonce)))
	azin = append(azin, nonce[:]...)
	azin = append(azin, azssb...)
	azin = append(azin, kh[:]...)
	azrt := backend.MAARuntimeData(azud)
	azrd := make([]byte, 64)
	azrs := sha256.Sum256(azrt)
	copy(azrd, azrs[:])
	v.AzureAttest.UserDataInput, v.AzureAttest.UserData = azin, azud
	v.AzureAttest.RuntimeData, v.AzureAttest.ReportData = string(azrt), azrd
	apo := &v.AzurePublicOutputs
	apo.ChallengeRoot, apo.PolicyRoot, apo.PlatformCommitment = nonce[:], azpr[:], azpc[:]
	apo.ConfigState, apo.KeyOrigin = azssb[32:313], azssb[313:353]

	// The Nitro signer: the same setup state, its own setup_hash.
	ni := statementNitroSetup(t)
	nipr, nipc, nish := must1(ni.PolicyRoot()), must1(ni.PlatformCommitment()), must1(ni.Hash())
	if nipr != pr {
		t.Fatal("the Nitro sample has another policy_root")
	}
	v.NitroSetup.Human, v.NitroSetup.Bytes = string(must(ni.Format())), must(ni.Encode())
	v.NitroSetup.PolicyRoot, v.NitroSetup.PlatformSalt, v.NitroSetup.PrivatePart = nipr[:], ni.PlatformSalt[:], must(ni.PrivateBytes())
	v.NitroSetup.PlatformCommitment, v.NitroSetup.SetupHash = nipc[:], nish[:]
	nist := st
	nist.SetupHash = nish
	nissb := backend.AppendSetupState(nil, &nist)
	niin := binary.BigEndian.AppendUint16(nil, uint16(len(backend.AttestContext)))
	niin = append(niin, backend.AttestContext...)
	niin = binary.BigEndian.AppendUint16(niin, uint16(len(nonce)))
	niin = append(niin, nonce[:]...)
	niin = append(niin, nissb...)
	niin = append(niin, kh[:]...)
	v.NitroAttest.UserDataInput, v.NitroAttest.UserData = niin, backend.AttestUserData(nonce[:], &nist, kh)
	npo := &v.NitroPublicOutputs
	npo.ChallengeRoot, npo.PolicyRoot, npo.PlatformCommitment = nonce[:], nipr[:], nipc[:]
	npo.ConfigState, npo.KeyOrigin = nissb[32:313], nissb[313:353]

	// The measurement output: the sample's allowed GCP image, a CCE policy
	// hash, and three PCRs.
	var pcrs []byte
	for i := range 3 {
		p := sha512.Sum384([]byte(fmt.Sprintf("statement vector nitro pcr%d", i)))
		pcrs = append(pcrs, p[:]...)
	}
	hostData := vsum("azure cce policy")
	v.Measurement.Nitro = measurementVector(uint8(ImageNitro), pcrs)
	v.Measurement.Azure = measurementVector(uint8(ImageAzure), hostData[:])
	v.Measurement.GCP = measurementVector(uint8(ImageGCP), s.Locked.AllowedImageMeasurements[0].Measurement)

	// keygen_orders_hash of three generated keys from two DKG orders.
	oa, ob := vsum("dkg order a"), vsum("dkg order b")
	keyOrders := [][32]byte{ob, oa, ob}
	for _, o := range keyOrders {
		v.KeygenOrders.KeyOrders = append(v.KeygenOrders.KeyOrders, o[:])
	}
	lo, hi := oa, ob
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	v.KeygenOrders.Input = CtxKeygenOrders.Message(binary.BigEndian.AppendUint32(nil, 2), lo[:], hi[:])
	koh := backend.KeygenOrdersHash(keyOrders)
	v.KeygenOrders.Hash = koh[:]

	// key_release_hash: a locked AWS key policy (no kms:PutKeyPolicy for
	// anyone) and an immutable Azure release policy.
	v.KeyRelease.Nitro = keyReleaseVector(backend.KeyReleaseNitro,
		"arn", "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"origin", "AWS_KMS", "key_manager", "CUSTOMER", "multi_region", "\x00",
		"policy", `{"Version":"2012-10-17","Id":"signer-runner-enclave","Statement":[{"Sid":"EnclaveOnlyDataKeys","Effect":"Allow",`+
			`"Principal":{"AWS":"arn:aws:iam::111122223333:role/signer-parent"},"Action":["kms:Decrypt","kms:GenerateDataKey"],"Resource":"*",`+
			`"Condition":{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:PCR0":"`+strings.Repeat("ab", 48)+`"}}}]}`)
	v.KeyRelease.Azure = keyReleaseVector(backend.KeyReleaseAzure,
		"kid", "https://signer-poc-kv.vault.azure.net/keys/signer-1/0123456789abcdef0123456789abcdef",
		"exportable", "\x01", "immutable", "\x01", "content_type", "application/json; charset=utf-8",
		"policy", `{"version":"1.0.0","anyOf":[{"authority":"https://sharedweu.weu.attest.azure.net","allOf":[`+
			`{"claim":"x-ms-sevsnpvm-hostdata","equals":"`+strings.Repeat("cd", 32)+`"}]}]}`)

	out, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// The vectors file is what the code makes, and every value in it follows
// from the others by the formulas of docs/attestation-statement.md,
// recomputed here without the package's helpers.
func TestStatementVectors(t *testing.T) {
	if MaxTimeLock < 172800 {
		t.Skip("the sample's change delay (48 hours) is above the cap of this build flavour")
	}
	want := buildVectors(t)
	path := filepath.FromSlash(vectorsPath)
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to make it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from what the code makes (run with -update after a deliberate change)", vectorsPath)
	}

	var v struct {
		Setup struct {
			Human  string `json:"human"`
			Bytes  string `json:"bytes"`
			Leaves map[string][]struct {
				Name  string `json:"name"`
				Value string `json:"value"`
				Salt  string `json:"salt"`
				Hash  string `json:"hash"`
			} `json:"leaves"`
			Roots              map[string]string `json:"group_roots"`
			PolicyRoot         string            `json:"policy_root"`
			PlatformSalt       string            `json:"platform_salt"`
			PrivatePart        string            `json:"private_part"`
			PlatformCommitment string            `json:"platform_commitment"`
			SetupHash          string            `json:"setup_hash"`
		} `json:"setup"`
		Update struct {
			Body       string `json:"body"`
			GroupRoot  string `json:"group_root"`
			Header     string `json:"header"`
			UpdateHash string `json:"update_hash"`
		} `json:"update"`
		SetupState struct {
			Bytes string `json:"bytes"`
		} `json:"setup_state"`
		Attest struct {
			Nonce         string    `json:"nonce"`
			Keys          []vKeyHex `json:"keys"`
			KeysHash      string    `json:"keys_hash"`
			UserDataInput string    `json:"user_data_input"`
			UserData      string    `json:"user_data"`
			GCPEatNonce   string    `json:"gcp_eat_nonce"`
		} `json:"attest"`
		PublicOutputs struct {
			ChallengeRoot      string `json:"challenge_root"`
			PolicyRoot         string `json:"policy_root"`
			PlatformCommitment string `json:"platform_commitment"`
			ConfigState        string `json:"config_state"`
			KeyOrigin          string `json:"key_origin"`
		} `json:"public_outputs"`
		PrivateInputs struct {
			KeysHash string `json:"keys_hash"`
		} `json:"private_inputs"`
		AzureSetup struct {
			Human              string `json:"human"`
			Bytes              string `json:"bytes"`
			PolicyRoot         string `json:"policy_root"`
			PlatformSalt       string `json:"platform_salt"`
			PrivatePart        string `json:"private_part"`
			PlatformCommitment string `json:"platform_commitment"`
			SetupHash          string `json:"setup_hash"`
		} `json:"azure_setup"`
		AzureAttest struct {
			UserDataInput string `json:"user_data_input"`
			UserData      string `json:"user_data"`
			RuntimeData   string `json:"runtime_data"`
			ReportData    string `json:"report_data"`
		} `json:"azure_attest"`
		AzurePublicOutputs map[string]string `json:"azure_public_outputs"`
		NitroSetup         struct {
			Human              string `json:"human"`
			Bytes              string `json:"bytes"`
			PolicyRoot         string `json:"policy_root"`
			PlatformSalt       string `json:"platform_salt"`
			PrivatePart        string `json:"private_part"`
			PlatformCommitment string `json:"platform_commitment"`
			SetupHash          string `json:"setup_hash"`
		} `json:"nitro_setup"`
		NitroAttest struct {
			UserDataInput string `json:"user_data_input"`
			UserData      string `json:"user_data"`
		} `json:"nitro_attest"`
		NitroPublicOutputs map[string]string `json:"nitro_public_outputs"`
		Measurement        map[string]struct {
			Platform    uint8  `json:"platform"`
			Value       string `json:"value"`
			Input       string `json:"input"`
			Measurement string `json:"measurement"`
		} `json:"measurement"`
		KeygenOrders struct {
			KeyOrders []string `json:"key_orders"`
			Input     string   `json:"input"`
			Hash      string   `json:"keygen_orders_hash"`
		} `json:"keygen_orders"`
		KeyRelease map[string]struct {
			Platform uint8 `json:"platform"`
			Fields   []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"fields"`
			Input string `json:"input"`
			Hash  string `json:"key_release_hash"`
		} `json:"key_release"`
	}
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatal(err)
	}
	x := func(s string) []byte {
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		return b
	}
	eq := func(what string, a []byte, b string) {
		t.Helper()
		if !bytes.Equal(a, x(b)) {
			t.Errorf("%s: recomputed %x, file %s", what, a, b)
		}
	}

	// Leaves and roots.
	roots := map[string][32]byte{}
	for _, g := range []string{"public", "locked", "open"} {
		var hs [][32]byte
		for i, l := range v.Setup.Leaves[g] {
			val, salt := x(l.Value), x(l.Salt)
			h := sum("signer-policy-leaf-v1", []byte{byte(len(l.Name))}, []byte(l.Name), binary.BigEndian.AppendUint32(nil, uint32(len(val))), val, salt)
			eq(fmt.Sprintf("%s leaf %d (%s)", g, i, l.Name), h[:], l.Hash)
			hs = append(hs, h)
		}
		n := 1
		for n < len(hs) {
			n *= 2
		}
		level := append(hs, make([][32]byte, n-len(hs))...)
		for len(level) > 1 {
			var next [][32]byte
			for i := 0; i < len(level); i += 2 {
				next = append(next, sum("signer-policy-node-v1", level[i][:], level[i+1][:]))
			}
			level = next
		}
		roots[g] = level[0]
		r := level[0]
		eq(g+" root", r[:], v.Setup.Roots[g])
	}
	rp, rl, ro := roots["public"], roots["locked"], roots["open"]
	pr := sum("signer-policy-root-v1", rp[:], rl[:], ro[:])
	eq("policy_root", pr[:], v.Setup.PolicyRoot)
	pc := sum("signer-platform-commitment-v1", x(v.Setup.PlatformSalt), x(v.Setup.PrivatePart))
	eq("platform_commitment", pc[:], v.Setup.PlatformCommitment)
	sh := sum("signer-setup-v1", pr[:], pc[:])
	eq("setup_hash", sh[:], v.Setup.SetupHash)

	// The setup bytes are 'S', each group's leaf values and salts, the
	// platform salt and the private part; they decode to the human form.
	var b []byte
	b = append(b, 'S')
	for _, g := range []string{"public", "locked", "open"} {
		for _, l := range v.Setup.Leaves[g] {
			b = append(b, x(l.Value)...)
		}
		for _, l := range v.Setup.Leaves[g] {
			b = append(b, x(l.Salt)...)
		}
	}
	b = append(b, x(v.Setup.PlatformSalt)...)
	b = append(b, x(v.Setup.PrivatePart)...)
	eq("setup bytes", b, v.Setup.Bytes)
	s, err := DecodeSetup(b)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := ParseSetup("vectors", []byte(v.Setup.Human)); err != nil || !sameSetup(p, s) {
		t.Fatalf("the human form does not read to the bytes: %v", err)
	}

	// The update: the group root of its body's leaves, the header, its hash.
	ub, err := DecodeUpdateBody(x(v.Update.Body))
	if err != nil {
		t.Fatal(err)
	}
	ls := must1(ub.Locked.Leaves(ub.Salts))
	var uhs [][32]byte
	for _, l := range ls {
		uhs = append(uhs, sum("signer-policy-leaf-v1", []byte{byte(len(l.Name))}, []byte(l.Name), binary.BigEndian.AppendUint32(nil, uint32(len(l.Value))), l.Value, l.Salt[:]))
	}
	gr := MerkleRoot(uhs)
	eq("update group root", gr[:], v.Update.GroupRoot)
	hdr := slices.Concat(ub.ClusterID[:], ub.ChainHash[:], []byte{byte(ub.Group)}, binary.BigEndian.AppendUint64(nil, ub.Version),
		ub.PrevHash[:], binary.BigEndian.AppendUint64(nil, ub.ActivateAt), gr[:])
	eq("update header", hdr, v.Update.Header)
	uh := sum("signer-config-update-v1", hdr)
	eq("update hash", uh[:], v.Update.UpdateHash)
	if ub.PrevHash != roots["locked"] {
		t.Error("the update's prev_hash is not the locked root of the setup")
	}

	// SetupState starts with setup_hash and names the update as locked
	// version 1; the user data is SHA-256 of its input, eat_nonce its hex.
	ss := x(v.SetupState.Bytes)
	if len(ss) != 353 || !bytes.Equal(ss[:32], sh[:]) || binary.BigEndian.Uint64(ss[32:40]) != 1 || !bytes.Equal(ss[40:72], uh[:]) {
		t.Error("setup state layout")
	}
	var kin []byte
	keys := v.Attest.Keys
	slices.SortFunc(keys, func(a, b vKeyHex) int { return bytes.Compare(x(a.Pubkey), x(b.Pubkey)) })
	for _, k := range keys {
		kin = append(kin, x(k.Pubkey)...)
		kin = append(kin, x(k.SharePubkey)...)
	}
	kh := sha256.Sum256(kin)
	eq("keys_hash", kh[:], v.Attest.KeysHash)
	nonce := x(v.Attest.Nonce)
	in := slices.Concat(msg("signer-runner-attest-v1"), binary.BigEndian.AppendUint16(nil, uint16(len(nonce))), nonce, ss, kh[:])
	eq("user data input", in, v.Attest.UserDataInput)
	ud := sha256.Sum256(in)
	eq("user data", ud[:], v.Attest.UserData)
	if v.Attest.GCPEatNonce != hex.EncodeToString(ud[:]) {
		t.Error("eat_nonce is not the lower-case hex of the user data")
	}

	// The public outputs are the nonce, the two halves of setup_hash and
	// the rest of the setup state: config_state with the pending order
	// (kind at byte 240, here 2) and key_release_hash (281 to 312), and the
	// key origin. keys_hash stays private.
	po := &v.PublicOutputs
	eq("challenge_root", nonce, po.ChallengeRoot)
	eq("public policy_root", pr[:], po.PolicyRoot)
	eq("public platform_commitment", pc[:], po.PlatformCommitment)
	eq("config_state", ss[32:313], po.ConfigState)
	eq("key_origin", ss[313:353], po.KeyOrigin)
	eq("private keys_hash", kh[:], v.PrivateInputs.KeysHash)
	if ss[240] != 2 || bytes.Equal(ss[281:313], make([]byte, 32)) {
		t.Error("the sample's pending order or key_release_hash is not set")
	}

	// The Azure sample: the same policy_root, its own commitment and
	// setup_hash; the setup state with that setup_hash; the user data as
	// above; the runtime data the JSON object of section 6 and the report
	// data its SHA-256 and 32 zero bytes.
	as := &v.AzureSetup
	eq("azure policy_root", pr[:], as.PolicyRoot)
	apc := sum("signer-platform-commitment-v1", x(as.PlatformSalt), x(as.PrivatePart))
	eq("azure platform_commitment", apc[:], as.PlatformCommitment)
	ash := sum("signer-setup-v1", pr[:], apc[:])
	eq("azure setup_hash", ash[:], as.SetupHash)
	ab := slices.Concat(b[:len(b)-len(x(v.Setup.PlatformSalt))-len(x(v.Setup.PrivatePart))], x(as.PlatformSalt), x(as.PrivatePart))
	eq("azure setup bytes", ab, as.Bytes)
	azs, err := DecodeSetup(ab)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := ParseSetup("vectors", []byte(as.Human)); err != nil || !sameSetup(p, azs) {
		t.Fatalf("the Azure human form does not read to the bytes: %v", err)
	}
	if azs.Platform.Platform != PlatformAzure || azs.Platform.SealingKeyRelease.MAAEndpoint == "" {
		t.Error("the Azure sample is not an Azure setup with an MAA host")
	}
	ass := slices.Concat(ash[:], ss[32:])
	ain := slices.Concat(msg("signer-runner-attest-v1"), binary.BigEndian.AppendUint16(nil, uint16(len(nonce))), nonce, ass, kh[:])
	eq("azure user data input", ain, v.AzureAttest.UserDataInput)
	aud := sha256.Sum256(ain)
	eq("azure user data", aud[:], v.AzureAttest.UserData)
	if want := `{"signer-runner-identity":"` + hex.EncodeToString(aud[:]) + `"}`; v.AzureAttest.RuntimeData != want {
		t.Errorf("azure runtime data %q, want %q", v.AzureAttest.RuntimeData, want)
	}
	ard := sha256.Sum256([]byte(v.AzureAttest.RuntimeData))
	eq("azure report data", append(ard[:], make([]byte, 32)...), v.AzureAttest.ReportData)
	for name, want := range map[string][]byte{"challenge_root": nonce, "policy_root": pr[:], "platform_commitment": apc[:],
		"config_state": ss[32:313], "key_origin": ss[313:353]} {
		eq("azure public "+name, want, v.AzurePublicOutputs[name])
	}

	// The Nitro sample, the same way: no runtime data, the user data is the
	// NSM document's user_data.
	ns := &v.NitroSetup
	eq("nitro policy_root", pr[:], ns.PolicyRoot)
	npc := sum("signer-platform-commitment-v1", x(ns.PlatformSalt), x(ns.PrivatePart))
	eq("nitro platform_commitment", npc[:], ns.PlatformCommitment)
	nsh := sum("signer-setup-v1", pr[:], npc[:])
	eq("nitro setup_hash", nsh[:], ns.SetupHash)
	nb := slices.Concat(b[:len(b)-len(x(v.Setup.PlatformSalt))-len(x(v.Setup.PrivatePart))], x(ns.PlatformSalt), x(ns.PrivatePart))
	eq("nitro setup bytes", nb, ns.Bytes)
	nis, err := DecodeSetup(nb)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := ParseSetup("vectors", []byte(ns.Human)); err != nil || !sameSetup(p, nis) {
		t.Fatalf("the Nitro human form does not read to the bytes: %v", err)
	}
	if nis.Platform.Platform != PlatformNitro {
		t.Error("the Nitro sample is not a Nitro setup")
	}
	nss := slices.Concat(nsh[:], ss[32:])
	nin := slices.Concat(msg("signer-runner-attest-v1"), binary.BigEndian.AppendUint16(nil, uint16(len(nonce))), nonce, nss, kh[:])
	eq("nitro user data input", nin, v.NitroAttest.UserDataInput)
	nud := sha256.Sum256(nin)
	eq("nitro user data", nud[:], v.NitroAttest.UserData)
	for name, want := range map[string][]byte{"challenge_root": nonce, "policy_root": pr[:], "platform_commitment": npc[:],
		"config_state": ss[32:313], "key_origin": ss[313:353]} {
		eq("nitro public "+name, want, v.NitroPublicOutputs[name])
	}

	// The measurement output: H("signer-measurement-v1", platform:u8 ||
	// value), with the value of each platform's length.
	mlen := map[string]int{"nitro": 144, "azure": 32, "gcp": 32}
	mplat := map[string]uint8{"nitro": 1, "azure": 2, "gcp": 3}
	if len(v.Measurement) != 3 {
		t.Errorf("measurement has %d platforms", len(v.Measurement))
	}
	for p, m := range v.Measurement {
		val := x(m.Value)
		if m.Platform != mplat[p] || len(val) != mlen[p] {
			t.Errorf("measurement %s: platform %d, value of %d bytes", p, m.Platform, len(val))
		}
		min := slices.Concat(msg("signer-measurement-v1"), []byte{m.Platform}, val)
		eq("measurement input "+p, min, m.Input)
		mh := sha256.Sum256(min)
		eq("measurement "+p, mh[:], m.Measurement)
	}
	if v.Measurement["gcp"].Value != "0x"+hex.EncodeToString(s.Locked.AllowedImageMeasurements[0].Measurement) {
		t.Error("the GCP measurement is not the sample's allowed image")
	}

	// keygen_orders_hash: the distinct order hashes in ascending order,
	// their count as u32 first.
	var orders [][]byte
	for _, o := range v.KeygenOrders.KeyOrders {
		orders = append(orders, x(o))
	}
	slices.SortFunc(orders, bytes.Compare)
	orders = slices.CompactFunc(orders, bytes.Equal)
	oin := slices.Concat(msg("signer-keygen-orders-v1"), binary.BigEndian.AppendUint32(nil, uint32(len(orders))), slices.Concat(orders...))
	eq("keygen orders input", oin, v.KeygenOrders.Input)
	oh := sha256.Sum256(oin)
	eq("keygen_orders_hash", oh[:], v.KeygenOrders.Hash)
	if len(orders) != 2 || len(v.KeygenOrders.KeyOrders) != 3 {
		t.Error("the keygen orders example has no repeat")
	}

	// key_release_hash: the platform byte, then each field with its length
	// as u32, in the order section 5 lists them.
	names := map[string][]string{
		"nitro": {"arn", "origin", "key_manager", "multi_region", "policy"},
		"azure": {"kid", "exportable", "immutable", "content_type", "policy"},
	}
	platforms := map[string]uint8{"nitro": 1, "azure": 2}
	if len(v.KeyRelease) != len(names) {
		t.Errorf("key_release has %d platforms", len(v.KeyRelease))
	}
	for p, kr := range v.KeyRelease {
		rin := append(msg("signer-key-release-v1"), kr.Platform)
		var got []string
		for _, f := range kr.Fields {
			val := x(f.Value)
			rin = binary.BigEndian.AppendUint32(rin, uint32(len(val)))
			rin = append(rin, val...)
			got = append(got, f.Name)
		}
		if kr.Platform != platforms[p] || !slices.Equal(got, names[p]) {
			t.Errorf("key_release %s: platform %d, fields %v", p, kr.Platform, got)
		}
		eq("key release input "+p, rin, kr.Input)
		rh := sha256.Sum256(rin)
		eq("key_release_hash "+p, rh[:], kr.Hash)
	}
}

// vKeyHex is a key of the vectors file as read back.
type vKeyHex struct {
	Pubkey      string `json:"pubkey"`
	SharePubkey string `json:"share_pubkey"`
}

func sameSetup(a, b *Setup) bool { return bytes.Equal(must(a.Encode()), must(b.Encode())) }

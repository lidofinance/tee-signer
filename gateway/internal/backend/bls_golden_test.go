package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	blst "github.com/supranational/blst/bindings/go"
)

// Golden vectors for combine, recoverPubkey and VerifyBLS. The keys are
// fixed, so the bytes are too: they pin what the gateway returns, whatever
// BLS library is under it.

var (
	// fieldP is p, the modulus of the BLS12-381 base field.
	fieldP, _ = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
	// groupR is r, the order of the G1 and G2 subgroups.
	groupR, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

	popDST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	nulDST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

	goldenRoot = phase0.Root{0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e}
)

// fixedScalar is sha256(label) mod r, never zero for these labels.
func fixedScalar(label string) *big.Int {
	h := sha256.Sum256([]byte(label))

	return new(big.Int).Mod(new(big.Int).SetBytes(h[:]), groupR)
}

func blstKey(k *big.Int) *blst.SecretKey {
	var b [32]byte
	k.FillBytes(b[:])

	return new(blst.SecretKey).FromBEndian(b[:])
}

func blstPub(sk *blst.SecretKey) phase0.BLSPubKey {
	var pk phase0.BLSPubKey
	copy(pk[:], new(blst.P1Affine).From(sk).Compress())

	return pk
}

func blstSign(sk *blst.SecretKey, root phase0.Root, dst []byte) phase0.BLSSignature {
	var sig phase0.BLSSignature
	copy(sig[:], new(blst.P2Affine).Sign(sk, root[:], dst).Compress())

	return sig
}

// fixedSplit is a t-of-n split of a fixed polynomial: the secret at 0 and
// shares 1..n.
func fixedSplit(name string, t, n int) (*big.Int, []*big.Int) {
	coef := make([]*big.Int, t)
	for i := range coef {
		coef[i] = fixedScalar(fmt.Sprintf("tee-signer gateway golden %s a%d", name, i))
	}
	shares := make([]*big.Int, n)
	for x := 1; x <= n; x++ {
		y := new(big.Int)
		for i := t - 1; i >= 0; i-- { // Horner
			y.Mul(y, big.NewInt(int64(x))).Add(y, coef[i]).Mod(y, groupR)
		}
		shares[x-1] = y
	}

	return coef[0], shares
}

func sqrtFp(a *big.Int) (*big.Int, bool) {
	// p = 3 mod 4: a^((p+1)/4) is a root when a is a square.
	e := new(big.Int).Rsh(new(big.Int).Add(fieldP, big.NewInt(1)), 2)
	y := new(big.Int).Exp(a, e, fieldP)

	return y, new(big.Int).Exp(y, big.NewInt(2), fieldP).Cmp(new(big.Int).Mod(a, fieldP)) == 0
}

func fp48(v *big.Int) []byte {
	b := make([]byte, 48)
	v.FillBytes(b)

	return b
}

// g1NotInSubgroup is a compressed point of E(Fp): y^2 = x^3 + 4, outside
// the subgroup of order r. blst's uncompress refuses an x with no point.
func g1NotInSubgroup(t *testing.T) phase0.BLSPubKey {
	t.Helper()
	for x := int64(1); x < 1000; x++ {
		var pk phase0.BLSPubKey
		copy(pk[:], fp48(big.NewInt(x)))
		pk[0] |= 0x80
		p := new(blst.P1Affine).Uncompress(pk[:])
		if p == nil || p.InG1() {
			continue
		}

		return pk
	}
	t.Fatal("no G1 point outside the subgroup")

	return phase0.BLSPubKey{}
}

// g2NotInSubgroup is a compressed point of E'(Fp2): y^2 = x^3 + 4(1+i),
// with x in Fp, outside the subgroup of order r. blst's uncompress
// refuses an x with no point on the curve.
func g2NotInSubgroup(t *testing.T) phase0.BLSSignature {
	t.Helper()
	for x := int64(1); x < 1000; x++ {
		var sig phase0.BLSSignature
		// x = c0 + c1*i is written c1 then c0; here c1 = 0.
		copy(sig[48:], fp48(big.NewInt(x)))
		sig[0] |= 0x80
		p := new(blst.P2Affine).Uncompress(sig[:])
		if p == nil || p.InG2() {
			continue
		}

		return sig
	}
	t.Fatal("no G2 point outside the subgroup")

	return phase0.BLSSignature{}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// The pinned bytes, first made by the gateway on its earlier BLS library
// (herumi bls-eth-go-binary v1.36.1, ETH mode). Each is also the key or the
// signature of the secret at 0.
var goldenWant = map[string]string{
	"2of3/pubkey":    "94356d333606374edd21698b32784e3f22ed680de180fda93fa5693b9c0305a034fecf8aea1c05276a980b17f5b6859c",
	"2of3/signature": "ae1d557cd391aa02a3d16483ecf8f65bd6ab65b39738aa5c3a058acf64e6cda26028d4563952ee7d6fc5c166b988c94803ec9821dbe2fd8f86611605fb4b8048f0c729b15b1fad3add64212731523e10f6aad762270ff4886c82440c91c99d41",
	"3of4/pubkey":    "a7639f2d6a5bd778633a0a3d6e8058500573278e6c1af65034afbb52c33aec97f5da97b45a9a19349e4e11280bc85b1d",
	"3of4/signature": "a54182013cfe8c5dc2ba79a51211b6b6c691294957faeaf5dd775dafa301b1d3a2e46ad039a2b430e81a185753a7f55d16a5100966be42dd8fd0e28189405caebac0e10d23d937c9f3a89cb97a0713c6ffd97d961808642c1b3a162570b21642",
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want, ok := goldenWant[name]
	if !ok {
		t.Errorf("golden %s: no pinned value; got %x", name, got)
		return
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("golden %s: got %x, want %s", name, got, want)
	}
}

func TestGoldenCombineAndRecover(t *testing.T) {
	for _, c := range []struct {
		name    string
		t, n    int
		subsets [][]uint64
	}{
		{"2of3", 2, 3, [][]uint64{{1, 2}, {1, 3}, {2, 3}, {3, 1}, {1, 2, 3}}},
		{"3of4", 3, 4, [][]uint64{{1, 2, 3}, {1, 2, 4}, {2, 3, 4}, {4, 1, 3}, {1, 2, 3, 4}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			secret, shares := fixedSplit(c.name, c.t, c.n)
			fullSK := blstKey(secret)
			wantPK, wantSig := blstPub(fullSK), blstSign(fullSK, goldenRoot, popDST)
			pks := make([]phase0.BLSPubKey, c.n)
			sigs := make([]phase0.BLSSignature, c.n)
			for i, s := range shares {
				sk := blstKey(s)
				pks[i], sigs[i] = blstPub(sk), blstSign(sk, goldenRoot, popDST)
			}
			checkGolden(t, c.name+"/pubkey", wantPK[:])
			checkGolden(t, c.name+"/signature", wantSig[:])
			for _, ids := range c.subsets {
				var ps []phase0.BLSPubKey
				var ss []phase0.BLSSignature
				for _, id := range ids {
					ps = append(ps, pks[id-1])
					ss = append(ss, sigs[id-1])
				}
				sig, err := combine(ids, ss)
				if err != nil {
					t.Fatalf("combine %v: %v", ids, err)
				}
				checkGolden(t, c.name+"/signature", sig[:])
				pk, err := recoverPubkey(ids, ps)
				if err != nil {
					t.Fatalf("recoverPubkey %v: %v", ids, err)
				}
				checkGolden(t, c.name+"/pubkey", pk[:])
				if err := VerifyBLS(pk, goldenRoot, sig); err != nil {
					t.Fatalf("subset %v: combined signature does not verify: %v", ids, err)
				}
			}
			// Below the threshold the result is some other point.
			if c.t > 2 {
				sig, err := combine([]uint64{1, 2}, sigs[:2])
				if err != nil || sig == wantSig {
					t.Fatalf("t-1 partials: %x, %v", sig, err)
				}
			}
		})
	}
}

func TestGoldenCombineRefusals(t *testing.T) {
	_, shares := fixedSplit("2of3", 2, 3)
	var sigs []phase0.BLSSignature
	var pks []phase0.BLSPubKey
	for _, s := range shares {
		sk := blstKey(s)
		sigs = append(sigs, blstSign(sk, goldenRoot, popDST))
		pks = append(pks, blstPub(sk))
	}
	var junkSig phase0.BLSSignature
	copy(junkSig[:], mustHex(t, "ff"))
	var junkPK phase0.BLSPubKey
	copy(junkPK[:], mustHex(t, "ff"))

	for _, c := range []struct {
		name string
		ids  []uint64
		sigs []phase0.BLSSignature
	}{
		{"index 0", []uint64{0, 1}, sigs[:2]},
		{"same index twice", []uint64{1, 1}, sigs[:2]},
		{"malformed partial", []uint64{1, 2}, []phase0.BLSSignature{sigs[0], junkSig}},
		{"partial outside G2 subgroup", []uint64{1, 2}, []phase0.BLSSignature{sigs[0], g2NotInSubgroup(t)}},
		{"no partials", nil, nil},
	} {
		got, err := combine(c.ids, c.sigs)
		t.Logf("combine %s: err=%v", c.name, err)
		if err == nil {
			t.Errorf("combine %s: no error, got %x", c.name, got)
		}
	}
	for _, c := range []struct {
		name string
		ids  []uint64
		pks  []phase0.BLSPubKey
	}{
		{"index 0", []uint64{0, 1}, pks[:2]},
		{"same index twice", []uint64{1, 1}, pks[:2]},
		{"malformed key", []uint64{1, 2}, []phase0.BLSPubKey{pks[0], junkPK}},
		{"key outside G1 subgroup", []uint64{1, 2}, []phase0.BLSPubKey{pks[0], g1NotInSubgroup(t)}},
		{"no keys", nil, nil},
	} {
		got, err := recoverPubkey(c.ids, c.pks)
		t.Logf("recoverPubkey %s: err=%v", c.name, err)
		if err == nil {
			t.Errorf("recoverPubkey %s: no error, got %x", c.name, got)
		}
	}
}

func TestGoldenVerifyBLS(t *testing.T) {
	sk := blstKey(fixedScalar("tee-signer gateway golden verify"))
	other := blstKey(fixedScalar("tee-signer gateway golden verify other"))
	pk, sig := blstPub(sk), blstSign(sk, goldenRoot, popDST)
	var infPK phase0.BLSPubKey
	infPK[0] = 0xc0
	var infSig phase0.BLSSignature
	infSig[0] = 0xc0
	var zeroPK phase0.BLSPubKey     // no compression flag
	var zeroSig phase0.BLSSignature // no compression flag
	pBytes := fp48(fieldP)          // x = p is not a field element
	var bigXPK phase0.BLSPubKey
	copy(bigXPK[:], pBytes)
	bigXPK[0] |= 0x80
	var notOnCurve phase0.BLSPubKey // an x where x^3 + 4 has no square root mod p
	for x := int64(1); ; x++ {
		if _, ok := sqrtFp(big.NewInt(x*x*x + 4)); !ok {
			copy(notOnCurve[:], fp48(big.NewInt(x)))
			notOnCurve[0] |= 0x80
			break
		}
	}

	for _, c := range []struct {
		name string
		pk   phase0.BLSPubKey
		root phase0.Root
		sig  phase0.BLSSignature
		ok   bool
	}{
		{"good", pk, goldenRoot, sig, true},
		{"wrong root", pk, phase0.Root{9}, sig, false},
		{"wrong key", blstPub(other), goldenRoot, sig, false},
		{"other key's signature", pk, goldenRoot, blstSign(other, goldenRoot, popDST), false},
		{"NUL ciphersuite (not proof of possession)", pk, goldenRoot, blstSign(sk, goldenRoot, nulDST), false},
		{"infinity pubkey", infPK, goldenRoot, sig, false},
		{"infinity signature", pk, goldenRoot, infSig, false},
		{"infinity pubkey and signature", infPK, goldenRoot, infSig, false},
		{"pubkey without compression flag", zeroPK, goldenRoot, sig, false},
		{"signature without compression flag", pk, goldenRoot, zeroSig, false},
		{"pubkey x >= p", bigXPK, goldenRoot, sig, false},
		{"pubkey not on the curve", notOnCurve, goldenRoot, sig, false},
		{"pubkey outside G1 subgroup", g1NotInSubgroup(t), goldenRoot, sig, false},
		{"signature outside G2 subgroup", pk, goldenRoot, g2NotInSubgroup(t), false},
	} {
		err := VerifyBLS(c.pk, c.root, c.sig)
		t.Logf("VerifyBLS %s: err=%v", c.name, err)
		if (err == nil) != c.ok {
			t.Errorf("VerifyBLS %s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

//go:build nts

package ntscore

import (
	"bytes"
	"testing"
)

// Deterministic randomized tests, the Rust core's random_input.rs before
// the port: garbage and mutated packets into both parsers. A panic fails
// the test; the package must return an error instead. The PRNG is
// splitmix64 with fixed seeds, so every run feeds the same inputs. The
// fuzz targets in fuzz_test.go carry on from here with the fuzzing engine.

// testRng is splitmix64. The same seed gives the same sequence on every run.
type testRng uint64

func (r *testRng) next() uint64 {
	*r += 0x9e37_79b9_7f4a_7c15
	z := uint64(*r)
	z = (z ^ (z >> 30)) * 0xbf58_476d_1ce4_e5b9
	z = (z ^ (z >> 27)) * 0x94d0_49bb_1331_11eb
	return z ^ (z >> 31)
}

// below is a number in 0..n, n > 0.
func (r *testRng) below(n int) int { return int(r.next() % uint64(n)) }

func (r *testRng) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.next())
	}
	return b
}

func testRounds(t testing.TB) int {
	if testing.Short() {
		return 2_000
	}
	return 20_000
}

// mutate is one random change: flip, set, insert or delete octets, cut
// the end, add to the end, or write a random 16-bit length at a random
// place.
func mutate(rng *testRng, good []byte) []byte {
	m := append([]byte(nil), good...)
	for k := 1 + rng.below(3); k > 0; k-- {
		at := rng.below(max(len(m), 1))
		switch c := rng.below(7); {
		case c == 0 && len(m) > 0:
			m[at] ^= 1 << rng.below(8)
		case c == 1 && len(m) > 0:
			m[at] = byte(rng.next())
		case c == 2:
			at = min(at, len(m))
			m = append(m[:at], append([]byte{byte(rng.next())}, m[at:]...)...)
		case c == 3 && len(m) > 0:
			m = append(m[:at], m[at+1:]...)
		case c == 4:
			m = m[:rng.below(len(m)+1)]
		case c == 5:
			m = append(m, rng.bytes(1+rng.below(64))...)
		case c == 6 && len(m) >= 2:
			at := rng.below(len(m) - 1)
			v := []uint16{0, 1, 2, 3, 4, 15, 16, 28, 0x7fff, 0xffff, uint16(rng.next())}[rng.below(11)]
			m[at], m[at+1] = byte(v>>8), byte(v)
		}
	}
	return m
}

// checkKE runs both parsers on buf and reports whether it parsed.
func checkKE(t testing.TB, buf []byte) bool {
	t.Helper()
	if n, done, err := KEComplete(buf); err == nil && done && (n > len(buf) || n > KEMaxResponseLen) {
		t.Fatalf("response length %d of %d octets", n, len(buf))
	}
	r, err := ParseKEResponse(buf)
	if err != nil {
		return false
	}
	if len(r.Cookies) < 1 || len(r.Cookies) > MaxCookies {
		t.Fatalf("%d cookies", len(r.Cookies))
	}
	for _, c := range r.Cookies {
		if len(c) < 1 || len(c) > MaxCookieLen {
			t.Fatalf("cookie of %d octets", len(c))
		}
	}
	if len(r.Server) > MaxServerName {
		t.Fatalf("server name of %d octets", len(r.Server))
	}
	return true
}

func TestKEGarbageAndMutations(t *testing.T) {
	rng := testRng(0x4b45_0001)
	good := goodKEResponse()
	rounds, accepted := testRounds(t), 0
	for i := 0; i < rounds; i++ {
		// Garbage: random length, random octets; half of them start with a
		// valid-looking record header so the parser gets past the first one.
		g := rng.bytes(rng.below(600))
		if rng.below(2) == 0 && len(g) >= 4 {
			g[0] &= 0x80
			g[1] = byte(rng.below(9))
			g[2] = 0
			g[3] = byte(rng.below(40))
		}
		checkKE(t, g)
		if checkKE(t, mutate(&rng, good)) {
			accepted++
		}
	}
	t.Logf("NTS-KE: %d garbage and %d mutated responses, %d mutated ones still valid", rounds, rounds, accepted)
}

func randomRequest(t testing.TB, rng *testRng, placeholders int) ([]byte, *PendingRequest) {
	t.Helper()
	in := RequestInput{Transmit: NTPTimestamp(rng.next()), Cookie: rep(0xc0, 100), Placeholders: placeholders}
	copy(in.UniqueID[:], rng.bytes(UniqueIDLen))
	copy(in.Nonce[:], rng.bytes(NonceLen))
	packet, req, err := BuildRequest(testKey(t, testC2S), &in)
	if err != nil {
		t.Fatal(err)
	}
	return packet, req
}

func TestNTPGarbageAndMutations(t *testing.T) {
	rng := testRng(0x4e54_5001)
	s2c := testKey(t, testS2C)
	rounds, accepted, kod := testRounds(t), 0, 0
	for round := 0; round < rounds; round++ {
		placeholders := rng.below(MaxPlaceholders + 1)
		packet, req := randomRequest(t, &rng, placeholders)
		read := serverReadRequest(testC2S, packet)
		if read == nil {
			t.Fatal("the server refuses the request")
		}
		r := goodReply()
		r.cookies = nil
		for i := 0; i <= placeholders; i++ {
			r.cookies = append(r.cookies, rep(byte(i), 4+rng.below(120)))
		}
		r.nonce = rng.bytes(1 + rng.below(32))
		good := serverResponse(testS2C, read, &r)

		// Garbage after a real header start, so the field parser is reached.
		g := rng.bytes(rng.below(1200))
		if round%2 == 0 && len(g) >= 48 {
			copy(g[:48], good[:48])
		}
		if v, err := req.Verify(s2c, g); err == nil && v.Time != nil {
			t.Fatalf("round %d: garbage accepted", round)
		}

		m := mutate(&rng, good)
		v, err := req.Verify(s2c, m)
		switch {
		case err == nil && v.Time != nil:
			// Only a change that changed nothing, or octets added after the
			// end, may leave a response valid: those octets are
			// unauthenticated fields and are discarded.
			if len(m) < len(good) || !bytes.Equal(m[:len(good)], good) {
				t.Fatalf("round %d: a changed response was accepted", round)
			}
			if len(v.Time.Cookies) > placeholders+1 {
				t.Fatalf("round %d: %d cookies", round, len(v.Time.Cookies))
			}
			accepted++
		case err == nil:
			if m[1] != 0 {
				t.Fatalf("round %d: a KoD needs stratum 0", round)
			}
			kod++
		}
		// The real response still works after the refused ones.
		if !req.Answered() {
			if v, err := req.Verify(s2c, good); err != nil || v.Time == nil {
				t.Fatalf("round %d: the real response refused after a mutated one: %v", round, err)
			}
		}
	}
	t.Logf("NTP: %d garbage and %d mutated responses, %d mutated ones accepted (unchanged, or octets added after the end), %d KoD",
		rounds, rounds, accepted, kod)
}

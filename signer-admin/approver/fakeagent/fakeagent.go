// Package fakeagent is a gpg-agent for tests. It serves, on a unix socket,
// the Assuan commands that admin/approver's openpgp: backend sends, and
// signs as gpg-agent does with an Ed25519 key on an OpenPGP card: the
// message is the digest SETHASH named, and only a digest of its hash's
// length passes (scdaemon's rule in scd/app-openpgp.c, do_sign).
package fakeagent

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Agent is one fake gpg-agent with one key.
type Agent struct {
	// Path is the socket; Grip names the key (not a real keygrip).
	Path, Grip string
	priv       ed25519.PrivateKey
	ln         net.Listener

	mu     sync.Mutex
	signed [][]byte
	descs  []string
}

// Last returns the last message the key signed and the last SETKEYDESC
// text, and how many messages it signed.
func (a *Agent) Last() (msg []byte, desc string, n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.signed) > 0 {
		msg = a.signed[len(a.signed)-1]
	}
	if len(a.descs) > 0 {
		desc = a.descs[len(a.descs)-1]
	}
	return msg, desc, len(a.signed)
}

// digestLen is the digest length of each SETHASH --hash name.
var digestLen = map[string]int{"sha1": 20, "rmd160": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64}

// Start serves an agent with the Ed25519 key of seed until the test ends.
func Start(t testing.TB, seed []byte) *Agent {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	g := sha1.Sum(priv.Public().(ed25519.PublicKey))
	// A short directory: a unix socket path has room for about 100 bytes.
	dir, err := os.MkdirTemp("", "fakeagent")
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Path: filepath.Join(dir, "S.gpg-agent"), Grip: strings.ToUpper(hex.EncodeToString(g[:])), priv: priv}
	if a.ln, err = net.Listen("unix", a.Path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.ln.Close(); os.RemoveAll(dir) })
	go func() {
		for {
			c, err := a.ln.Accept()
			if err != nil {
				return
			}
			go a.serve(c)
		}
	}()
	return a
}

// Public is the agent's public key.
func (a *Agent) Public() ed25519.PublicKey { return a.priv.Public().(ed25519.PublicKey) }

func (a *Agent) serve(c net.Conn) {
	defer c.Close()
	w := bufio.NewWriter(c)
	reply := func(lines ...string) {
		for _, l := range lines {
			w.WriteString(l + "\n")
		}
		w.Flush()
	}
	reply("OK Pleased to meet you")
	var digest []byte
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		cmd, arg, _ := strings.Cut(sc.Text(), " ")
		switch cmd {
		case "OPTION", "RESET":
			reply("OK")
		case "BYE":
			reply("OK closing connection")
			return
		case "READKEY", "SIGKEY":
			if arg != a.Grip {
				reply("ERR 67108881 No secret key <GPG Agent>")
				continue
			}
			if cmd == "READKEY" {
				reply("D "+escape(list("public-key", list("ecc", sexp("curve", "Ed25519"), sexp("flags", "eddsa"),
					sexp("q", "\x40"+string(a.Public()))))), "OK")
				continue
			}
			reply("OK")
		case "SETKEYDESC":
			a.mu.Lock()
			a.descs = append(a.descs, strings.ReplaceAll(arg, "+", " "))
			a.mu.Unlock()
			reply("OK")
		case "SETHASH":
			opt, hx, _ := strings.Cut(arg, " ")
			name, ok := strings.CutPrefix(opt, "--hash=")
			d, err := hex.DecodeString(hx)
			if !ok || err != nil || digestLen[name] == 0 {
				reply("ERR 536870957 invalid hash algorithm <GPG Agent>")
				continue
			}
			if len(d) != digestLen[name] {
				reply("ERR 83886161 Invalid value <SCD>")
				continue
			}
			digest = d
			reply("OK")
		case "PKSIGN":
			if digest == nil {
				reply("ERR 67108925 No data <GPG Agent>")
				continue
			}
			sig := ed25519.Sign(a.priv, digest)
			a.mu.Lock()
			a.signed = append(a.signed, digest)
			a.mu.Unlock()
			reply("D "+escape(list("sig-val", list("eddsa", sexp("r", string(sig[:32])), sexp("s", string(sig[32:]))))), "OK")
		default:
			reply("ERR 536871187 Unknown IPC command <GPG Agent>")
		}
	}
}

// sexp makes the canonical s-expression (head v): v an atom.
func sexp(head, v string) string { return "(" + atom(head) + atom(v) + ")" }

// list makes (head items...): items encoded already.
func list(head string, items ...string) string {
	return "(" + atom(head) + strings.Join(items, "") + ")"
}

func atom(s string) string { return fmt.Sprintf("%d:%s", len(s), s) }

// escape percent-escapes a D line as gpg-agent does.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%', '\r', '\n':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

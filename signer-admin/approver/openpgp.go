package approver

// The openpgp: scheme: an Ed25519 key that gpg-agent holds, on an OpenPGP
// card (a YubiKey's OpenPGP applet) or in the agent's own key store. The
// URI names the key by its keygrip: openpgp:KEYGRIP, the 40 hex digits
// that gpg --with-keygrip prints for the signing subkey.
//
// What the card signs. Sign sends gpg-agent the 32-byte hashed message
// (setupwire.ApprovalMessage) as a SHA-256 digest:
//
//	SIGKEY <keygrip>
//	SETKEYDESC <text for the PIN prompt>
//	SETHASH --hash=sha256 <the 32 bytes as hex>
//	PKSIGN
//
// For a key on a card the agent wraps the 32 bytes in SHA-256's DigestInfo
// (agent/divert-scd.c, divert_pksign) and scdaemon takes the DigestInfo off
// again and sends the card the bare 32 bytes in PSO: COMPUTE DIGITAL
// SIGNATURE (scd/app-openpgp.c, do_sign). An EdDSA card signs its input
// as the Ed25519 message; that is how every OpenPGP EdDSA signature is
// made, over the hash of the signed data (RFC 9580, 5.2.4). A key in the
// agent's store signs the same 32 bytes as the PureEdDSA message
// (agent/pksign.c, do_encode_eddsa). Either way the answer is a plain
// Ed25519 signature over the hashed message, which the runner's
// setupwire.VerifyApproval takes unchanged.
//
// scdaemon hands a card 20, 28, 32, 48 or 64 bytes only, so this backend
// signs the hashed form only. The agent does not check a card's EdDSA
// signature; Sign checks it under the public key before it returns it.

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// AgentSocket returns the path of gpg-agent's socket. It asks gpgconf,
// which honours GNUPGHOME, and starts the agent if it is not running.
// Tests replace it.
var AgentSocket = func() (string, error) {
	// --launch is a no-op when the agent runs already.
	_ = exec.Command("gpgconf", "--launch", "gpg-agent").Run()
	out, err := exec.Command("gpgconf", "--list-dirs", "agent-socket").Output()
	if err != nil {
		return "", fmt.Errorf("gpgconf --list-dirs agent-socket: %w (is GnuPG installed?)", err)
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return "", errors.New("gpgconf names no agent socket")
	}
	return p, nil
}

// agentTimeout bounds one signature: the PIN prompt and the touch.
const agentTimeout = 3 * time.Minute

// openpgpSigner is an Ed25519 key in gpg-agent.
type openpgpSigner struct {
	grip string // 40 upper-case hex digits
	pub  ed25519.PublicKey
}

func (o *openpgpSigner) Public() ed25519.PublicKey { return o.pub }

// HashedOnly: scdaemon refuses the direct form's long messages.
func (o *openpgpSigner) HashedOnly() bool { return true }

// openOpenPGP reads the public key of the keygrip from gpg-agent. That needs
// neither the card nor its PIN: the agent keeps the public key in the
// card key's stub file.
func openOpenPGP(rest string) (Signer, error) {
	grip := strings.ToUpper(rest)
	if b, err := hex.DecodeString(grip); err != nil || len(b) != 20 {
		return nil, fmt.Errorf("openpgp:%s: want openpgp:KEYGRIP, the 40 hex digits gpg --with-keygrip -K prints as Keygrip for the signing subkey", rest)
	}
	a, err := dialAgent()
	if err != nil {
		return nil, err
	}
	defer a.close()
	data, err := a.transact("READKEY " + grip)
	if err != nil {
		return nil, fmt.Errorf("gpg-agent has no key %s: %w", grip, err)
	}
	pub, err := ed25519FromSexp(data)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", grip, err)
	}
	return &openpgpSigner{grip: grip, pub: pub}, nil
}

// Sign has gpg-agent sign the 32-byte message with the key; for a card key
// the card asks for its PIN (once per agent cache) and a touch (per the
// card's touch policy).
func (o *openpgpSigner) Sign(message []byte) ([]byte, error) {
	if len(message) != 32 {
		return nil, fmt.Errorf("an OpenPGP key signs 32 bytes, the hashed form, not %d", len(message))
	}
	a, err := dialAgent()
	if err != nil {
		return nil, err
	}
	defer a.close()
	a.sessionOptions()
	desc := fmt.Sprintf("signer-admin: approver signature with key %s over the hashed message %x. Compare it with what signer-admin show prints.", o.grip, message)
	for _, cmd := range []string{
		"SIGKEY " + o.grip,
		"SETKEYDESC " + assuanEscape(desc),
		"SETHASH --hash=sha256 " + hex.EncodeToString(message),
	} {
		if _, err := a.transact(cmd); err != nil {
			return nil, fmt.Errorf("gpg-agent %s: %w", strings.Fields(cmd)[0], err)
		}
	}
	data, err := a.transact("PKSIGN")
	if err != nil {
		return nil, fmt.Errorf("gpg-agent PKSIGN with key %s: %w", o.grip, err)
	}
	sig, err := ed25519SigFromSexp(data)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(o.pub, message, sig) {
		return nil, fmt.Errorf("the signature of key %s does not verify under its public key", o.grip)
	}
	return sig, nil
}

// HashedOnly reports whether s signs the hashed form only (an OpenPGP key).
func HashedOnly(s Signer) bool {
	h, ok := s.(interface{ HashedOnly() bool })
	return ok && h.HashedOnly()
}

// ---- Assuan client ----

type agentConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialAgent() (*agentConn, error) {
	path, err := AgentSocket()
	if err != nil {
		return nil, err
	}
	conn, err := dialAssuan(path)
	if err != nil {
		return nil, fmt.Errorf("gpg-agent at %s: %w", path, err)
	}
	conn.SetDeadline(time.Now().Add(agentTimeout))
	a := &agentConn{conn: conn, r: bufio.NewReaderSize(conn, 4096)}
	if _, err := a.read(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("gpg-agent at %s: greeting: %w", path, err)
	}
	return a, nil
}

// dialAssuan connects to an Assuan socket: a unix socket, or on Windows a
// file that holds the TCP port on 127.0.0.1 and a 16-byte nonce to send
// first (libassuan's socket emulation).
func dialAssuan(path string) (net.Conn, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return net.Dial("unix", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	port, nonce, ok := bytes.Cut(b, []byte("\n"))
	if p, err := strconv.Atoi(string(port)); !ok || err != nil || p <= 0 || p > 65535 || len(nonce) != 16 {
		return nil, errors.New("not an Assuan socket file (port and 16-byte nonce)")
	}
	conn, err := net.Dial("tcp", "127.0.0.1:"+string(port))
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(nonce); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (a *agentConn) close() {
	fmt.Fprint(a.conn, "BYE\n")
	a.conn.Close()
}

// sessionOptions tells the agent where a terminal PIN prompt goes, as gpg
// does. On Windows and macOS the prompt is a window and these are unset.
func (a *agentConn) sessionOptions() {
	for opt, env := range map[string]string{"ttyname": "GPG_TTY", "ttytype": "TERM", "display": "DISPLAY"} {
		if v := os.Getenv(env); v != "" && !strings.ContainsAny(v, "\r\n") {
			a.transact("OPTION " + opt + "=" + v)
		}
	}
}

// transact sends one command and returns its data lines, joined.
func (a *agentConn) transact(cmd string) ([]byte, error) {
	if len(cmd) > 1000 {
		return nil, errors.New("assuan line too long")
	}
	if _, err := fmt.Fprintf(a.conn, "%s\n", cmd); err != nil {
		return nil, err
	}
	return a.read()
}

// read reads lines up to OK or ERR and returns the data of the D lines.
func (a *agentConn) read() ([]byte, error) {
	var data []byte
	for {
		line, err := a.r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		line = strings.TrimSuffix(line, "\n")
		switch {
		case line == "OK" || strings.HasPrefix(line, "OK "):
			return data, nil
		case strings.HasPrefix(line, "ERR "):
			code, text, _ := strings.Cut(line[4:], " ")
			return nil, fmt.Errorf("%s (gpg error %s)", assuanUnescape(text), code)
		case strings.HasPrefix(line, "D "):
			data = append(data, assuanUnescape(line[2:])...)
		case strings.HasPrefix(line, "INQUIRE "):
			// This client sets no option that makes the agent ask
			// anything; cancel what it asks.
			if _, err := fmt.Fprint(a.conn, "CAN\n"); err != nil {
				return nil, err
			}
		case strings.HasPrefix(line, "S "), strings.HasPrefix(line, "#"):
		default:
			return nil, fmt.Errorf("unexpected assuan line %q", line)
		}
	}
}

// assuanEscape percent-escapes a SETKEYDESC argument: spaces become plus
// signs, so a literal plus is escaped too.
func assuanEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ':
			b.WriteByte('+')
		case c == '%' || c == '+' || c < 0x20:
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func assuanUnescape(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(v))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

// ---- canonical S-expressions ----

// sexp is an atom (atom != nil) or a list.
type sexp struct {
	atom []byte
	list []sexp
}

func parseSexp(b []byte) (sexp, error) {
	s, rest, err := parseSexpAt(b)
	if err != nil {
		return sexp{}, err
	}
	if len(rest) != 0 {
		return sexp{}, errors.New("s-expression: trailing bytes")
	}
	return s, nil
}

func parseSexpAt(b []byte) (sexp, []byte, error) {
	if len(b) == 0 {
		return sexp{}, nil, errors.New("s-expression: truncated")
	}
	if b[0] == '(' {
		var l sexp
		b = b[1:]
		for {
			if len(b) == 0 {
				return sexp{}, nil, errors.New("s-expression: unclosed list")
			}
			if b[0] == ')' {
				if l.list == nil {
					l.list = []sexp{}
				}
				return l, b[1:], nil
			}
			e, rest, err := parseSexpAt(b)
			if err != nil {
				return sexp{}, nil, err
			}
			l.list = append(l.list, e)
			b = rest
		}
	}
	colon := bytes.IndexByte(b, ':')
	if colon < 1 || colon > 9 {
		return sexp{}, nil, errors.New("s-expression: bad atom length")
	}
	n, err := strconv.Atoi(string(b[:colon]))
	if err != nil || n < 0 || len(b)-colon-1 < n {
		return sexp{}, nil, errors.New("s-expression: bad atom length")
	}
	return sexp{atom: b[colon+1 : colon+1+n]}, b[colon+1+n:], nil
}

// head is the first atom of a list, or "".
func (s sexp) head() string {
	if len(s.list) == 0 || s.list[0].atom == nil {
		return ""
	}
	return string(s.list[0].atom)
}

// find returns the first list below s whose head is name.
func (s sexp) find(name string) (sexp, bool) {
	for _, e := range s.list {
		if e.head() == name {
			return e, true
		}
		if f, ok := e.find(name); ok {
			return f, true
		}
	}
	return sexp{}, false
}

// value is the second element of (name value), an atom.
func (s sexp) value(name string) []byte {
	f, ok := s.find(name)
	if !ok || len(f.list) < 2 {
		return nil
	}
	return f.list[1].atom
}

// ed25519FromSexp reads an Ed25519 key from the agent's public key
// s-expression: (public-key(ecc(curve Ed25519)(flags eddsa)(q 0x40||key))).
func ed25519FromSexp(b []byte) (ed25519.PublicKey, error) {
	s, err := parseSexp(b)
	if err != nil {
		return nil, err
	}
	if s.head() != "public-key" {
		return nil, fmt.Errorf("not a public key: %q", s.head())
	}
	ecc, ok := s.find("ecc")
	if !ok {
		return nil, errors.New("not an elliptic curve key; an approver key is Ed25519")
	}
	switch curve := string(ecc.value("curve")); curve {
	case "Ed25519", "ed25519", "1.3.6.1.4.1.11591.15.1":
	case "Curve25519", "cv25519", "1.3.6.1.4.1.3029.1.5.1":
		return nil, errors.New("a Curve25519 encryption key; use the Ed25519 signing subkey")
	default:
		return nil, fmt.Errorf("curve %q; an approver key is Ed25519", curve)
	}
	q := ecc.value("q")
	if len(q) == 33 && q[0] == 0x40 {
		q = q[1:]
	}
	if len(q) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 point of %d bytes", len(q))
	}
	return ed25519.PublicKey(bytes.Clone(q)), nil
}

// ed25519SigFromSexp reads (sig-val(eddsa(r R)(s S))) into R||S. A value
// shorter than 32 bytes lost leading zero bytes on the way (an MPI) and gets
// them back, as gpg does.
func ed25519SigFromSexp(b []byte) ([]byte, error) {
	s, err := parseSexp(b)
	if err != nil {
		return nil, err
	}
	if s.head() != "sig-val" {
		return nil, fmt.Errorf("not a signature: %q", s.head())
	}
	alg, ok := s.find("eddsa")
	if !ok {
		return nil, errors.New("not an EdDSA signature; is the key an Ed25519 key?")
	}
	sig := make([]byte, 0, ed25519.SignatureSize)
	for _, name := range []string{"r", "s"} {
		v := alg.value(name)
		if len(v) == 0 || len(v) > 32 {
			return nil, fmt.Errorf("EdDSA signature: %s of %d bytes", name, len(v))
		}
		sig = append(sig, make([]byte, 32-len(v))...)
		sig = append(sig, v...)
	}
	return sig, nil
}

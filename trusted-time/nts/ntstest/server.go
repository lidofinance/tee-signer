//go:build nts

// Package ntstest is an NTS-KE and NTS-protected NTP server for tests, on
// loopback. It is written from RFC 8915 apart from the Rust client and
// uses its own AES-SIV (siv.go), so client and server check each other.
// Nothing outside tests imports it.
package ntstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RFC 8915 section 5.1: the exporter label, and the context of NTPv4 with
// AEAD 15 for the C2S (0) and S2C (1) keys.
const exporterLabel = "EXPORTER-network-time-security"

var (
	contextC2S = []byte{0, 0, 0, 15, 0}
	contextS2C = []byte{0, 0, 0, 15, 1}
)

type keyPair struct{ c2s, s2c []byte }

// Store maps cookies to the keys of their NTS-KE session, like a server's
// cookie encryption (RFC 8915 section 6) without the encryption.
type Store struct {
	mu sync.Mutex
	m  map[[16]byte]keyPair
}

// NewStore is an empty cookie store, shared by a KE and an NTP server.
func NewStore() *Store { return &Store{m: map[[16]byte]keyPair{}} }

// cookie is a fresh 100-octet cookie for k: a random ID and zero filler.
func (s *Store) cookie(k keyPair) []byte {
	c := make([]byte, 100)
	_, _ = rand.Read(c[:16])
	var id [16]byte
	copy(id[:], c)
	s.mu.Lock()
	s.m[id] = k
	s.mu.Unlock()
	return c
}

func (s *Store) lookup(c []byte) (keyPair, bool) {
	if len(c) != 100 {
		return keyPair{}, false
	}
	var id [16]byte
	copy(id[:], c)
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.m[id]
	return k, ok
}

// Forget drops every cookie, so the next request gets an NTSN.
func (s *Store) Forget() {
	s.mu.Lock()
	s.m = map[[16]byte]keyPair{}
	s.mu.Unlock()
}

// Certificate makes a CA and a leaf for host valid from notBefore to
// notAfter, and returns the leaf and a pool with the CA.
func Certificate(host string, notBefore, notAfter time.Time) (tls.Certificate, *x509.CertPool, error) {
	cert, ca, err := newCertificate(host, notBefore, notAfter)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return cert, pool, nil
}

func newCertificate(host string, notBefore, notAfter time.Time) (tls.Certificate, *x509.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ntstest CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ca, nil
}

// KEOptions shape the NTS-KE responses.
type KEOptions struct {
	NTPServer string // Server record (4.1.7), if set
	NTPPort   uint16 // Port record (4.1.8), if set
	Cookies   int    // New Cookie records; 0 means 8
	NoALPN    bool   // do not offer ntske/1
	TLS12     bool   // only TLS 1.2
	ErrorCode int    // > 0: answer with an Error record of code ErrorCode-1
}

// KEServer is an NTS-KE server on 127.0.0.1.
type KEServer struct {
	Addr     string
	Sessions atomic.Int32
	ln       net.Listener
	store    *Store
	opts     KEOptions
}

// StartKE listens on a free loopback port.
func StartKE(cert tls.Certificate, store *Store, opts KEOptions) (*KEServer, error) {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if !opts.NoALPN {
		cfg.NextProtos = []string{"ntske/1"}
	}
	if opts.TLS12 {
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		return nil, err
	}
	s := &KEServer{Addr: ln.Addr().String(), ln: ln, store: store, opts: opts}
	go s.serve()
	return s, nil
}

// Close stops the server.
func (s *KEServer) Close() { s.ln.Close() }

func (s *KEServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c.(*tls.Conn))
	}
}

func record(critical bool, t uint16, body []byte) []byte {
	if critical {
		t |= 0x8000
	}
	r := binary.BigEndian.AppendUint16(nil, t)
	r = binary.BigEndian.AppendUint16(r, uint16(len(body)))
	return append(r, body...)
}

func (s *KEServer) handle(c *tls.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		return
	}
	s.Sessions.Add(1)
	// Read records until End of Message (RFC 8915 section 4).
	for {
		var h [4]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(h[2:]))
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		if binary.BigEndian.Uint16(h[:2])&0x7fff == 0 {
			break
		}
	}
	var resp []byte
	if s.opts.ErrorCode > 0 {
		resp = append(record(true, 2, binary.BigEndian.AppendUint16(nil, uint16(s.opts.ErrorCode-1))), record(true, 0, nil)...)
		_, _ = c.Write(resp)
		return
	}
	st := c.ConnectionState()
	c2s, err1 := st.ExportKeyingMaterial(exporterLabel, contextC2S, 32)
	s2c, err2 := st.ExportKeyingMaterial(exporterLabel, contextS2C, 32)
	if err1 != nil || err2 != nil {
		return
	}
	resp = append(resp, record(true, 1, []byte{0, 0})...)
	resp = append(resp, record(false, 4, []byte{0, 15})...)
	n := s.opts.Cookies
	if n == 0 {
		n = 8
	}
	for i := 0; i < n; i++ {
		resp = append(resp, record(false, 5, s.store.cookie(keyPair{c2s, s2c}))...)
	}
	if s.opts.NTPServer != "" {
		resp = append(resp, record(true, 6, []byte(s.opts.NTPServer))...)
	}
	if s.opts.NTPPort != 0 {
		resp = append(resp, record(true, 7, binary.BigEndian.AppendUint16(nil, s.opts.NTPPort))...)
	}
	resp = append(resp, record(true, 0, nil)...)
	_, _ = c.Write(resp)
}

// NTPOptions shape the NTP responses.
type NTPOptions struct {
	Offset     time.Duration // the server clock is time.Now() + Offset
	Hold       time.Duration // time between receive and transmit (T3 - T2)
	Stratum    uint8         // 0 means 1
	Precision  int8          // 0 means -20
	RootDelay  time.Duration
	RootDisp   time.Duration
	Kiss       string // "RATE", "DENY", ...: answer with this Kiss-o'-Death
	Drop       bool   // do not answer
	BadAuth    bool   // flip a bit of the authenticator
	ZeroRefTim bool   // reference timestamp 0
	// Clock is the server clock before Offset; nil means time.Now.
	Clock func() time.Time
}

// NTPServer is an NTS-protected NTP server on 127.0.0.1.
type NTPServer struct {
	Addr     string
	Port     uint16
	Requests atomic.Int64
	conn     *net.UDPConn
	store    *Store
	mu       sync.Mutex
	opts     NTPOptions
}

// StartNTP listens on a free loopback UDP port.
func StartNTP(store *Store, opts NTPOptions) (*NTPServer, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	a := conn.LocalAddr().(*net.UDPAddr)
	s := &NTPServer{Addr: a.String(), Port: uint16(a.Port), conn: conn, store: store, opts: opts}
	go s.serve()
	return s, nil
}

// Set changes the options for the next requests.
func (s *NTPServer) Set(opts NTPOptions) {
	s.mu.Lock()
	s.opts = opts
	s.mu.Unlock()
}

// Close stops the server.
func (s *NTPServer) Close() { s.conn.Close() }

// ntpTime is t as an NTP timestamp (RFC 5905 section 6), era 0 or 1 by
// wrapping.
func ntpTime(t time.Time) uint64 {
	secs := uint64(t.Unix()+2_208_988_800) & 0xffff_ffff
	frac := (uint64(t.Nanosecond()) << 32) / 1_000_000_000
	return secs<<32 | frac
}

func ntpShort(d time.Duration) uint32 { return uint32(d.Nanoseconds() * 65536 / 1_000_000_000) }

func field(t uint16, body []byte) []byte {
	padded := (len(body) + 3) / 4 * 4
	f := binary.BigEndian.AppendUint16(nil, t)
	f = binary.BigEndian.AppendUint16(f, uint16(4+padded))
	f = append(f, body...)
	return append(f, make([]byte, padded-len(body))...)
}

type request struct {
	transmit     []byte
	poll         byte
	uid, cookie  []byte
	placeholders int
	authStart    int
	nonce, ct    []byte
}

// parse reads a client request (RFC 8915 section 5.7). nil if malformed.
func parse(p []byte) *request {
	if len(p) < 48 || p[0]&0x3f != 4<<3|3 {
		return nil
	}
	r := &request{transmit: p[40:48], poll: p[2]}
	for at := 48; at+4 <= len(p); {
		t := binary.BigEndian.Uint16(p[at:])
		l := int(binary.BigEndian.Uint16(p[at+2:]))
		if l < 16 || l%4 != 0 || at+l > len(p) {
			return nil
		}
		body := p[at+4 : at+l]
		switch t {
		case 0x0104:
			r.uid = body
		case 0x0204:
			r.cookie = body
		case 0x0304:
			r.placeholders++
		case 0x0404:
			nl := int(binary.BigEndian.Uint16(body))
			cl := int(binary.BigEndian.Uint16(body[2:]))
			nonceEnd := 4 + (nl+3)/4*4
			if 4+nl > len(body) || nonceEnd+cl > len(body) {
				return nil
			}
			r.authStart, r.nonce, r.ct = at, body[4:4+nl], body[nonceEnd:nonceEnd+cl]
			return r
		}
		at += l
	}
	return nil
}

func (s *NTPServer) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.Requests.Add(1)
		s.mu.Lock()
		o := s.opts
		s.mu.Unlock()
		recv := o.now().Add(o.Offset)
		p := append([]byte(nil), buf[:n]...)
		go func() {
			if out := s.answer(p, recv, o); out != nil {
				_, _ = s.conn.WriteToUDP(out, from)
			}
		}()
	}
}

func (s *NTPServer) answer(p []byte, recv time.Time, o NTPOptions) []byte {
	r := parse(p)
	if r == nil || r.uid == nil || r.cookie == nil || o.Drop {
		return nil
	}
	k, ok := s.store.lookup(r.cookie)
	kiss := o.Kiss
	if !ok {
		kiss = "NTSN" // RFC 8915 section 5.7: unknown cookie
	} else if _, ok := Open(k.c2s, p[:r.authStart], r.nonce, r.ct); !ok {
		kiss = "NTSN"
	}
	if o.Hold > 0 {
		time.Sleep(o.Hold)
	}
	stratum, prec := o.Stratum, o.Precision
	if stratum == 0 {
		stratum = 1
	}
	if prec == 0 {
		prec = -20
	}
	h := make([]byte, 48)
	h[0] = 4<<3 | 4
	h[1], h[2], h[3] = stratum, r.poll, byte(prec)
	binary.BigEndian.PutUint32(h[4:], ntpShort(o.RootDelay))
	binary.BigEndian.PutUint32(h[8:], ntpShort(o.RootDisp))
	copy(h[12:], "GPS\x00")
	ref := ntpTime(recv.Add(-16 * time.Second))
	if o.ZeroRefTim {
		ref = 0
	}
	binary.BigEndian.PutUint64(h[16:], ref)
	copy(h[24:], r.transmit)
	binary.BigEndian.PutUint64(h[32:], ntpTime(recv))
	if kiss != "" {
		// RFC 5905 section 7.4: leap 3, stratum 0, the code in the reference ID.
		h[0] |= 3 << 6
		h[1] = 0
		copy(h[12:], kiss)
		binary.BigEndian.PutUint64(h[40:], ntpTime(recv))
		return append(h, field(0x0104, r.uid)...)
	}
	binary.BigEndian.PutUint64(h[40:], ntpTime(o.now().Add(o.Offset)))
	out := append(h, field(0x0104, r.uid)...)
	var plain []byte
	for i := 0; i < 1+r.placeholders; i++ {
		plain = append(plain, field(0x0204, s.store.cookie(k))...)
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	ct := Seal(k.s2c, out, nonce, plain)
	if o.BadAuth {
		ct[0] ^= 1
	}
	body := binary.BigEndian.AppendUint16(nil, 16)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ct)))
	body = append(body, nonce...)
	body = append(body, ct...)
	body = append(body, make([]byte, (len(ct)+3)/4*4-len(ct))...)
	return append(out, field(0x0404, body)...)
}

func (o NTPOptions) now() time.Time {
	if o.Clock != nil {
		return o.Clock()
	}
	return time.Now()
}

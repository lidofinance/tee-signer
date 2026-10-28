// Package remote is the backend.Backend that talks to an enclave runner
// over the wire protocol (package wire) on TCP, a unix socket or vsock.
//
// On TCP to a runner on the network (GCP, Azure) use WithTLS: mutual TLS
// 1.3 where the client presents its certificate and checks the runner's
// key against the runner's attested identity before sending anything
// else. The runner's slashing protection and policy do not depend on the
// caller; the check makes sure the caller reaches the attested runner.
// On AWS the enclave listens on vsock and the parent instance, which
// forwards the traffic, is not trusted, so the runner serves mutual TLS
// there as well. A client built by attest/runnerclient reaches it over TCP,
// through a plain forwarder on the parent that copies bytes (the TLS ends
// inside the enclave). A client on the parent can also dial vsock with
// WithTLS.
package remote

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// VerifyFunc checks an identity's attestation document: platform signature
// chain, measurements, and that the document binds
// id.Attestation.UserData. The client has already checked that UserData
// equals backend.IdentityUserData(nonce, id).
type VerifyFunc func(ctx context.Context, nonce []byte, id *backend.Identity) error

// Client implements backend.Backend. Requests go one at a time over one
// connection. After an I/O error, a timeout or a bad response the client
// drops that connection and dials a new one for the next request, with all
// the checks of dial (TLS key binding and attestation) again.
//
// A caller whose context ends stops waiting at once, whether it waits for
// its turn or for a dial. Two rules keep the client working when many
// callers give up while one connection is down, as the Dirk fork's callers
// do when a threshold of other signers has answered:
//
//   - A dial does not belong to the request that starts it. It runs in its
//     own context (bounded by the client timeout), so the cancellation of
//     that request does not abort it, and the connection it makes serves
//     the next request.
//   - A request whose context has ended before its turn is not sent. The
//     connection stays up, and the runner never sees the request.
//
// A request that is on the wire is not interrupted by its context: the
// connection would be out of step. It ends with its deadline.
type Client struct {
	addr    transport.Addr
	timeout time.Duration

	tlsCfg *tls.Config
	verify VerifyFunc
	pin    []byte

	// gate has room for one token. Its holder owns conn and nextID: it is
	// the only goroutine that sends on conn or replaces it. A caller waits
	// for the gate with its context.
	gate   chan struct{}
	conn   net.Conn
	nextID uint32
}

var _ backend.Backend = (*Client)(nil)

// The admin calls (imports, config updates, exit approvals, key
// generation, handovers) are in package remote/admin. A runner answers
// them only to a client of the admin role.

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-request timeout used when ctx has no deadline
// (default 10s). It also bounds each dial, from the TCP connection to the
// end of the attestation check.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithTLS runs every connection over TLS 1.3 with cfg (which carries the
// client certificate). The runner's certificate is self-signed inside the
// TEE, so instead of a CA the client binds it to the attestation: right
// after the handshake it sends IDENTITY with a fresh nonce, checks that
// the identity names the key the runner just presented, and calls verify
// (if not nil). Use WithTLSKeyPin as well or instead when the key is known.
func WithTLS(cfg *tls.Config, verify VerifyFunc) Option {
	return func(c *Client) { c.tlsCfg, c.verify = cfg, verify }
}

// WithTLSKeyPin accepts only a runner whose TLS key has this sha256
// (DER SubjectPublicKeyInfo).
func WithTLSKeyPin(sha256SPKI []byte) Option {
	return func(c *Client) { c.pin = append([]byte(nil), sha256SPKI...) }
}

// New returns a client for addr (see package transport). It does not
// connect until the first request.
func New(addr string, opts ...Option) (*Client, error) {
	a, err := transport.Parse(addr)
	if err != nil {
		return nil, err
	}
	c := &Client{addr: a, timeout: 10 * time.Second, gate: make(chan struct{}, 1)}
	for _, o := range opts {
		o(c)
	}
	if c.tlsCfg != nil && c.verify == nil && c.pin == nil {
		return nil, errors.New("remote: TLS needs an attestation verifier or a key pin")
	}
	return c, nil
}

// Addr returns the runner address.
func (c *Client) Addr() string { return c.addr.String() }

// exchange sends one request on conn and returns the decoded response.
func (c *Client) exchange(conn net.Conn, t wire.MsgType, payload []byte) ([]byte, error) {
	c.nextID++
	id := c.nextID
	if err := wire.WriteFrame(conn, wire.Frame{Type: t, ID: id, Payload: payload}); err != nil {
		return nil, err
	}
	f, err := wire.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if f.ID != id || f.Type != t|wire.ResponseFlag {
		return nil, fmt.Errorf("unexpected response %v id %d", f.Type, f.ID)
	}
	return f.Payload, nil
}

// SPKIHash is sha256 of a certificate's DER SubjectPublicKeyInfo.
func SPKIHash(rawSPKI []byte) []byte {
	h := sha256.Sum256(rawSPKI)
	return h[:]
}

// dial connects and, with TLS, binds the channel to the attested identity.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	conn, err := transport.Dial(ctx, c.addr)
	if err != nil || c.tlsCfg == nil {
		return conn, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(c.timeout))
	}
	cfg := c.tlsCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	// The certificate is self-signed in the TEE; it is checked against the
	// attested identity below instead of a CA.
	cfg.InsecureSkipVerify = true
	tc := tls.Client(conn, cfg)
	fail := func(err error) (net.Conn, error) { tc.Close(); return nil, fmt.Errorf("remote: %v: %w", c.addr, err) }
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(fmt.Errorf("tls handshake: %w", err))
	}
	peer := tc.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		return fail(errors.New("runner sent no certificate"))
	}
	got := SPKIHash(peer[0].RawSubjectPublicKeyInfo)
	if c.pin != nil && !bytes.Equal(got, c.pin) {
		return fail(fmt.Errorf("runner TLS key %x is not the pinned key %x", got, c.pin))
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fail(err)
	}
	id, err := c.identityOn(tc, nonce)
	if err != nil {
		return fail(fmt.Errorf("identity: %w", err))
	}
	if !bytes.Equal(id.TLSKeyHash, got) {
		return fail(fmt.Errorf("runner presented TLS key %x but its attested identity names %x", got, id.TLSKeyHash))
	}
	if c.verify != nil {
		if err := c.verify(ctx, nonce, id); err != nil {
			return fail(fmt.Errorf("attestation: %w", err))
		}
	}
	return tc, nil
}

func (c *Client) identityOn(conn net.Conn, nonce []byte) (*backend.Identity, error) {
	p, err := wire.EncodeAttest(nonce)
	if err != nil {
		return nil, err
	}
	resp, err := c.exchange(conn, wire.TypeIdentity, p)
	if err != nil {
		return nil, err
	}
	b, err := wire.DecodeResponse(resp)
	if err != nil {
		return nil, err
	}
	id, err := wire.DecodeIdentity(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(id.Attestation.UserData, backend.IdentityUserData(nonce, id)) {
		return nil, errors.New("attestation user data does not match the identity fields and nonce")
	}
	return id, nil
}

// acquire takes the gate. It gives up when ctx ends, and it does not hand
// the gate to a caller whose context has already ended.
func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		c.release()
		return err
	}
	return nil
}

func (c *Client) release() { <-c.gate }

// drop closes the connection, so that the next request dials a new one.
// The caller holds the gate.
func (c *Client) drop() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

type dialResult struct {
	conn net.Conn
	err  error
}

// startDial dials in its own goroutine and its own context. The context
// keeps the values of ctx but not its cancellation or deadline: the client
// timeout bounds the dial. The caller holds the gate and must either take
// the result or pass it to adopt.
func (c *Client) startDial(ctx context.Context) <-chan dialResult {
	res := make(chan dialResult, 1)
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	go func() {
		defer cancel()
		conn, err := c.dial(dctx)
		res <- dialResult{conn, err}
	}()
	return res
}

// adopt waits for a dial that its caller left behind, keeps the connection
// it made, and releases the gate the caller held.
func (c *Client) adopt(res <-chan dialResult) {
	if r := <-res; r.err == nil {
		c.conn = r.conn
	}
	c.release()
}

// RoundTrip sends one request of type t and returns the body of the
// answer, or the runner's refusal as a *backend.RefusedError. Package
// remote/admin builds the admin calls on it.
func (c *Client) RoundTrip(ctx context.Context, t wire.MsgType, payload []byte) ([]byte, error) {
	return c.roundTrip(ctx, t, payload)
}

func (c *Client) roundTrip(ctx context.Context, t wire.MsgType, payload []byte) ([]byte, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, fmt.Errorf("remote: %v: %w", t, err)
	}
	if c.conn == nil {
		res := c.startDial(ctx)
		select {
		case r := <-res:
			if r.err != nil {
				c.release()
				return nil, fmt.Errorf("remote: dial %v: %w", c.addr, r.err)
			}
			c.conn = r.conn
		case <-ctx.Done():
			// The caller gave up. The dial goes on and the next request
			// uses the connection it makes.
			go c.adopt(res)
			return nil, fmt.Errorf("remote: dial %v: %w", c.addr, ctx.Err())
		}
	}
	defer c.release()
	if err := ctx.Err(); err != nil {
		// Nothing was sent, so the connection stays.
		return nil, fmt.Errorf("remote: %v: %w", t, err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.timeout)
	}
	_ = c.conn.SetDeadline(deadline)
	resp, err := c.exchange(c.conn, t, payload)
	if err != nil {
		// A timeout or an error leaves the connection out of step, or
		// stalled. It is never used again.
		c.drop()
		return nil, fmt.Errorf("remote: %v: %w", t, err)
	}
	return wire.DecodeResponse(resp)
}

func (c *Client) PublicKeys(ctx context.Context) ([]backend.ValidatorKey, error) {
	b, err := c.roundTrip(ctx, wire.TypePublicKeys, nil)
	if err != nil {
		return nil, err
	}
	return wire.DecodeKeys(b)
}

// Sign is not retried here. The runner signs an exact repeat of the last
// attestation or block again (same signature), so a caller may resend.
func (c *Client) Sign(ctx context.Context, req backend.SignRequest) (backend.Signature, error) {
	p, err := wire.EncodeSign(req)
	if err != nil {
		return backend.Signature{}, err
	}
	b, err := c.roundTrip(ctx, wire.TypeSign, p)
	if err != nil {
		return backend.Signature{}, err
	}
	return wire.DecodeSignature(b)
}

// Attest returns the runner's attestation document for nonce. AttestState
// returns the setup state it binds too.
func (c *Client) Attest(ctx context.Context, nonce []byte) (*backend.Attestation, error) {
	_, a, err := c.AttestState(ctx, nonce)
	return a, err
}

// AttestState returns the runner's setup state and its attestation document
// for nonce. The document binds backend.AttestUserData(nonce, state,
// backend.KeysHash(keys)); the caller checks that with the keys of
// PublicKeys, and verifies the document.
func (c *Client) AttestState(ctx context.Context, nonce []byte) (*backend.SetupState, *backend.Attestation, error) {
	p, err := wire.EncodeAttest(nonce)
	if err != nil {
		return nil, nil, err
	}
	b, err := c.roundTrip(ctx, wire.TypeAttest, p)
	if err != nil {
		return nil, nil, err
	}
	return wire.DecodeAttestResponse(b)
}

// Identity returns the runner's attested identity for nonce, after checking
// that the attestation user data matches the identity fields. The caller
// verifies the document itself (see VerifyFunc).
func (c *Client) Identity(ctx context.Context, nonce []byte) (*backend.Identity, error) {
	p, err := wire.EncodeAttest(nonce)
	if err != nil {
		return nil, err
	}
	b, err := c.roundTrip(ctx, wire.TypeIdentity, p)
	if err != nil {
		return nil, err
	}
	id, err := wire.DecodeIdentity(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(id.Attestation.UserData, backend.IdentityUserData(nonce, id)) {
		return nil, errors.New("remote: identity: attestation user data does not match the identity fields and nonce")
	}
	return id, nil
}

func (c *Client) Health(ctx context.Context) (*backend.Health, error) {
	b, err := c.roundTrip(ctx, wire.TypeHealth, nil)
	if err != nil {
		return nil, err
	}
	return wire.DecodeHealth(b)
}

// DevVerifier accepts only the dev platform's unsigned JSON document and
// checks that it carries the nonce and the user data. It proves nothing
// about the code that answered; it exists for tests on the dev platform.
// Real verifiers check the platform's signature chain and measurements
// (Nitro COSE_Sign1 and PCRs, Confidential Space or MAA JWT claims):
// Config.Verify in package github.com/lidofinance/tee-signer/attestation-verify/identity does that and has
// the VerifyFunc signature. The Dirk fork's adapter and the import tools
// pick a verifier by name ("dev" is this one; "azure-maa", "aws-nitro" and
// "gcp-cs" check an MAA token, an NSM document and a Confidential Space
// token) with package github.com/lidofinance/tee-signer/attestation-verify/runnerclient.
func DevVerifier(_ context.Context, nonce []byte, id *backend.Identity) error {
	a := id.Attestation
	if a.Platform != "dev" || a.Format != "dev-json" {
		return fmt.Errorf("DevVerifier: platform %q format %q is not the dev platform", a.Platform, a.Format)
	}
	var doc struct {
		Nonce    []byte `json:"nonce"`
		UserData []byte `json:"user_data"`
	}
	if err := json.Unmarshal(a.Document, &doc); err != nil {
		return fmt.Errorf("DevVerifier: %w", err)
	}
	if !bytes.Equal(doc.Nonce, nonce) || !bytes.Equal(doc.UserData, a.UserData) {
		return errors.New("DevVerifier: document does not carry the nonce and user data")
	}
	return nil
}

// Close closes the connection, after the request on it ends. The client
// dials again for the next request.
func (c *Client) Close() error {
	c.gate <- struct{}{}
	defer c.release()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

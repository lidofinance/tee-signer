// Package hostagent is the parent-instance side of a Nitro deployment and
// its client inside the enclave. The enclave has no disk and no network,
// so the agent on the parent keeps the sealed blobs and hands out the
// instance role credentials the enclave needs to call KMS.
//
// Everything the agent does is untrusted: it can drop, replay or roll back
// blobs and withhold credentials. Blobs are sealed by the enclave, so it
// cannot read or forge them. Rollback is why the runner uses the restart
// floor on Nitro.
//
// Protocol: wire framing (backend/wire) with JSON payloads and these types:
//
//	0x41 GET   {"key"}            -> {"value": base64} or status NOT_FOUND
//	0x42 PUT   {"key","value"}    -> {}
//	0x43 LIST  {"prefix"}         -> {"keys": [...]}
//	0x44 CREDS {}                 -> {"access_key_id","secret_access_key","session_token","expiration"}
//	0x45 EXIT  {"text"}           -> {}
//	0x46 SETUP {}                 -> {"value": base64} or status NOT_FOUND
//
// SETUP hands the runner its setup (research/setup-phase.md, section 3) at
// every start, before any KMS call: the binary setup the parent keeps in a
// file (hostagent -setup). It is not secret. A host that hands over other
// bytes gets a runner with another setup_hash; once key release takes
// setup_hash (a later step), that runner gets other keys too.
//
// EXIT carries the runner's fatal error line, the one it prints to stderr
// before it exits. A production enclave has no console, so without it a
// failed start shows only as the enclave going away. The runner sends
// nothing else this way. The agent keeps at most MaxExitText bytes of
// printable ASCII and hands the line to Server.Exit (the command writes it
// to a file and its log).
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

const (
	TypeGet   wire.MsgType = 0x41
	TypePut   wire.MsgType = 0x42
	TypeList  wire.MsgType = 0x43
	TypeCreds wire.MsgType = 0x44
	TypeExit  wire.MsgType = 0x45
	TypeSetup wire.MsgType = 0x46

	statusNotFound backend.Status = 1404

	// MaxExitText bounds an EXIT line, on both sides.
	MaxExitText = 2048
)

type request struct {
	Key    string `json:"key,omitempty"`
	Value  []byte `json:"value,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Text   string `json:"text,omitempty"`
}

// ExitText cuts s to MaxExitText bytes and replaces every byte that is not
// printable ASCII with '?', so the line is one plain line in a file or log.
func ExitText(s string) string {
	if len(s) > MaxExitText {
		s = s[:MaxExitText]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

type response struct {
	Value []byte   `json:"value,omitempty"`
	Keys  []string `json:"keys,omitempty"`
}

// Credentials are temporary AWS credentials.
type Credentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
}

// Server serves a store and, optionally, credentials.
type Server struct {
	Store platform.Store
	Creds func(ctx context.Context) (Credentials, error) // nil: CREDS unsupported
	// Exit gets the runner's fatal error line (already through ExitText).
	// nil: EXIT unsupported.
	Exit func(text string)
	// Setup returns the setup's bytes. nil: SETUP answers NOT_FOUND.
	Setup func() ([]byte, error)
	Log   *slog.Logger
}

// ExitFile is a Server.Exit that logs the line and replaces path with
// "<UTC time> <line>\n" (mode 0600, written to a temp file and renamed).
func ExitFile(path string, log *slog.Logger) func(text string) {
	return func(text string) {
		if log != nil {
			log.Error("runner exit report", "text", text)
		}
		line := time.Now().UTC().Format(time.RFC3339) + " " + text + "\n"
		tmp := path + ".tmp"
		err := os.WriteFile(tmp, []byte(line), 0o600)
		if err == nil {
			err = os.Rename(tmp, path)
		}
		if err != nil && log != nil {
			log.Warn("exit report not written", "file", path, "err", err)
		}
	}
}

func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, c)
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	for {
		f, err := wire.ReadFrame(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && s.Log != nil {
				s.Log.Warn("hostagent read", "err", err)
			}
			return
		}
		body, err := s.do(ctx, f)
		payload := wire.EncodeOK(body)
		if err != nil {
			payload = wire.EncodeError(err)
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: f.Type | wire.ResponseFlag, ID: f.ID, Payload: payload}); err != nil {
			return
		}
	}
}

func (s *Server) do(ctx context.Context, f wire.Frame) ([]byte, error) {
	var req request
	if len(f.Payload) > 0 {
		if err := json.Unmarshal(f.Payload, &req); err != nil {
			return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
		}
	}
	var resp any = response{}
	switch f.Type {
	case TypeGet:
		v, err := s.Store.Get(req.Key)
		if errors.Is(err, platform.ErrNotFound) {
			return nil, &backend.RefusedError{Code: statusNotFound, Detail: req.Key}
		}
		if err != nil {
			return nil, err
		}
		resp = response{Value: v}
	case TypePut:
		if err := s.Store.Put(req.Key, req.Value); err != nil {
			return nil, err
		}
	case TypeList:
		keys, err := s.Store.List(req.Prefix)
		if err != nil {
			return nil, err
		}
		resp = response{Keys: keys}
	case TypeCreds:
		if s.Creds == nil {
			return nil, backend.Refused(backend.StatusUnsupported, "no credentials source")
		}
		c, err := s.Creds(ctx)
		if err != nil {
			return nil, err
		}
		resp = c
	case TypeExit:
		if s.Exit == nil {
			return nil, backend.Refused(backend.StatusUnsupported, "no exit report sink")
		}
		s.Exit(ExitText(req.Text))
	case TypeSetup:
		if s.Setup == nil {
			return nil, &backend.RefusedError{Code: statusNotFound, Detail: "no setup"}
		}
		v, err := s.Setup()
		if err != nil {
			return nil, err
		}
		resp = response{Value: v}
	default:
		return nil, backend.Refused(backend.StatusUnsupported, "type %v", f.Type)
	}
	return json.Marshal(resp)
}

// Client talks to a Server. It implements platform.Store.
type Client struct {
	addr transport.Addr

	mu   sync.Mutex
	conn net.Conn
	id   uint32
}

var _ platform.Store = (*Client)(nil)

func NewClient(addr string) (*Client, error) {
	a, err := transport.Parse(addr)
	if err != nil {
		return nil, err
	}
	return &Client{addr: a}, nil
}

func (c *Client) call(t wire.MsgType, req any, out any) error {
	return c.callWithin(t, req, out, 30*time.Second)
}

func (c *Client) callWithin(t wire.MsgType, req any, out any, limit time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		conn, err := transport.Dial(ctx, c.addr)
		cancel()
		if err != nil {
			return fmt.Errorf("hostagent: dial %v: %w", c.addr, err)
		}
		c.conn = conn
	}
	p, err := json.Marshal(req)
	if err != nil {
		return err
	}
	_ = c.conn.SetDeadline(time.Now().Add(limit))
	c.id++
	fail := func(err error) error {
		c.conn.Close()
		c.conn = nil
		return fmt.Errorf("hostagent: %w", err)
	}
	if err := wire.WriteFrame(c.conn, wire.Frame{Type: t, ID: c.id, Payload: p}); err != nil {
		return fail(err)
	}
	f, err := wire.ReadFrame(c.conn)
	if err != nil {
		return fail(err)
	}
	if f.ID != c.id || f.Type != t|wire.ResponseFlag {
		return fail(errors.New("unexpected response"))
	}
	body, err := wire.DecodeResponse(f.Payload)
	if err != nil {
		if backend.StatusOf(err) == statusNotFound {
			return platform.ErrNotFound
		}
		return err
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

func (c *Client) Get(key string) ([]byte, error) {
	var r response
	if err := c.call(TypeGet, request{Key: key}, &r); err != nil {
		return nil, err
	}
	return r.Value, nil
}

func (c *Client) Put(key string, val []byte) error {
	return c.call(TypePut, request{Key: key, Value: val}, nil)
}

func (c *Client) List(prefix string) ([]string, error) {
	var r response
	err := c.call(TypeList, request{Prefix: prefix}, &r)
	return r.Keys, err
}

// Credentials asks the agent for AWS credentials.
func (c *Client) Credentials(ctx context.Context) (Credentials, error) {
	var cr Credentials
	err := c.call(TypeCreds, struct{}{}, &cr)
	return cr, err
}

// ReportExit sends the runner's fatal error line to the agent, waiting at
// most 5 s. Only for the line the runner also prints before it exits: the
// parent is not trusted and keeps what it gets.
func (c *Client) ReportExit(text string) error {
	return c.callWithin(TypeExit, request{Text: ExitText(text)}, nil, 5*time.Second)
}

// Setup asks the agent for the setup. platform.ErrNotFound: the agent has
// none.
func (c *Client) Setup() ([]byte, error) {
	var r response
	if err := c.call(TypeSetup, struct{}{}, &r); err != nil {
		return nil, err
	}
	return r.Value, nil
}

// SetupChannel is the Nitro setup channel (runner/setup.Channel): SETUP
// from the host agent at Addr, the fixed vsock:3:7101 in the image. Read
// tries again while the agent cannot be reached, until ctx ends; an agent
// that answers without a setup ends it at once.
type SetupChannel struct {
	Addr  string
	Retry time.Duration // pause between tries; 0: 2 s

	client *Client
}

func (s *SetupChannel) Read(ctx context.Context) ([]byte, error) {
	if s.client == nil {
		c, err := NewClient(s.Addr)
		if err != nil {
			return nil, err
		}
		s.client = c
	}
	retry := s.Retry
	if retry <= 0 {
		retry = 2 * time.Second
	}
	for {
		v, err := s.client.Setup()
		var refused *backend.RefusedError
		switch {
		case err == nil:
			return v, nil
		case errors.Is(err, platform.ErrNotFound):
			return nil, errors.New("the host agent has no setup (start it with -setup FILE)")
		case errors.As(err, &refused):
			// The agent answered: trying again gives the same answer.
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no setup from the host agent at %s: %w", s.Addr, err)
		case <-time.After(retry):
		}
	}
}

func (s *SetupChannel) String() string { return "host agent " + s.Addr }

// ReportExit hands the runner's fatal error line to the agent, for a
// failure before the platform exists (a refused setup).
func (s *SetupChannel) ReportExit(text string) {
	if s.client == nil {
		c, err := NewClient(s.Addr)
		if err != nil {
			return
		}
		s.client = c
	}
	_ = s.client.ReportExit(text)
}

// Package agentclient is the enclave side of the Nitro host agent: the
// client the runner uses for its sealed blobs, the KMS credentials, its
// setup and its exit report. The agent on the parent (package hostagent)
// is not trusted; agentwire describes the protocol.
package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform-aws/hostagent/agentwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

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
		if backend.StatusOf(err) == agentwire.StatusNotFound {
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
	var r agentwire.Response
	if err := c.call(agentwire.TypeGet, agentwire.Request{Key: key}, &r); err != nil {
		return nil, err
	}
	return r.Value, nil
}

func (c *Client) Put(key string, val []byte) error {
	return c.call(agentwire.TypePut, agentwire.Request{Key: key, Value: val}, nil)
}

func (c *Client) List(prefix string) ([]string, error) {
	var r agentwire.Response
	err := c.call(agentwire.TypeList, agentwire.Request{Prefix: prefix}, &r)
	return r.Keys, err
}

// Credentials asks the agent for AWS credentials.
func (c *Client) Credentials(ctx context.Context) (agentwire.Credentials, error) {
	var cr agentwire.Credentials
	err := c.call(agentwire.TypeCreds, struct{}{}, &cr)
	return cr, err
}

// ReportExit sends the runner's fatal error line to the agent, waiting at
// most 5 s. Only for the line the runner also prints before it exits: the
// parent is not trusted and keeps what it gets.
func (c *Client) ReportExit(text string) error {
	return c.callWithin(agentwire.TypeExit, agentwire.Request{Text: agentwire.ExitText(text)}, nil, 5*time.Second)
}

// Setup asks the agent for the setup. platform.ErrNotFound: the agent has
// none.
func (c *Client) Setup() ([]byte, error) {
	var r agentwire.Response
	if err := c.call(agentwire.TypeSetup, struct{}{}, &r); err != nil {
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

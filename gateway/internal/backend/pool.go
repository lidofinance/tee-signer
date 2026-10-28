package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
)

// maxConnections bounds the connections to one signer.
const maxConnections = 16

// runner is what the gateway asks of one TEE signer.
type runner interface {
	PublicKeys(ctx context.Context) ([]proto.ValidatorKey, error)
	Sign(ctx context.Context, req proto.SignRequest) (proto.Signature, error)
	Close() error
}

// node is one TEE signer behind a few runner clients. Each client holds
// one connection and sends one request at a time on it. It dials when it
// has none, and runnerclient checks every new connection before a request
// goes on it: TLS 1.3 with the client certificate, the build flavour and
// the chain mark of the signer's certificate, IDENTITY with a fresh nonce,
// the attestation document with its verifier and the setup pins, and the
// TLS key the attested identity names (and tls_key_pin, if set). A client
// drops its connection after an I/O error or a timeout, so a restarted
// signer goes through every check again. A request takes an idle client
// and gives it back.
type node struct {
	addr string
	idle chan *runnerclient.Client
	all  []*runnerclient.Client
}

// newNode makes size clients for conn. It does not connect.
func newNode(conn runnerclient.Connection, size int, opts ...runnerclient.Option) (*node, error) {
	if size < 1 || size > maxConnections {
		return nil, fmt.Errorf("connections must be 1 to %d", maxConnections)
	}
	n := &node{addr: conn.Address, idle: make(chan *runnerclient.Client, size)}
	for range size {
		c, err := conn.New(opts...)
		if err != nil {
			_ = n.Close()

			return nil, err
		}
		n.all = append(n.all, c)
		n.idle <- c
	}

	return n, nil
}

// do runs f on an idle client. A call that failed on the connection
// itself (the signer closed it or reset it, as after a restart) runs once
// more on another client, which dials and checks a new connection when it
// has none. The signer signs an exact repeat of an attestation or block
// again with the same signature, so a SIGN may go twice. A refusal, a
// failed check, a timeout or the end of ctx is not tried again.
func (n *node) do(ctx context.Context, f func(*runnerclient.Client) error) error {
	for attempt := 1; ; attempt++ {
		var c *runnerclient.Client
		select {
		case c = <-n.idle:
		case <-ctx.Done():
			return fmt.Errorf("%s: no idle connection: %w", n.addr, ctx.Err())
		}
		err := f(c)
		n.idle <- c
		if err == nil || attempt == 2 || ctx.Err() != nil || !connectionLost(err) {
			return err
		}
	}
}

// connectionLost reports whether err says the connection ended under the
// request: the signer closed or reset it.
func connectionLost(err error) bool {
	var refused *proto.RefusedError
	if errors.As(err, &refused) {
		return false
	}

	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

func (n *node) PublicKeys(ctx context.Context) ([]proto.ValidatorKey, error) {
	var keys []proto.ValidatorKey
	err := n.do(ctx, func(c *runnerclient.Client) error {
		var err error
		keys, err = c.PublicKeys(ctx)

		return err
	})

	return keys, err
}

func (n *node) Sign(ctx context.Context, req proto.SignRequest) (proto.Signature, error) {
	var sig proto.Signature
	err := n.do(ctx, func(c *runnerclient.Client) error {
		var err error
		sig, err = c.Sign(ctx, req)

		return err
	})

	return sig, err
}

// Close closes every connection. A request on one ends first.
func (n *node) Close() error {
	var errs []error
	for _, c := range n.all {
		errs = append(errs, c.Close())
	}

	return errors.Join(errs...)
}

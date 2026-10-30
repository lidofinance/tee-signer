// Package forward is the network entry of an AWS signer: a plain byte
// forwarder that runs on the parent EC2 instance. It accepts TCP
// connections (where the signing client connects) and copies each one to a new
// connection to the enclave (vsock). It is not trusted and holds no
// secret: the mutual TLS 1.3 of the runner ends inside the enclave, and
// the forwarder only sees the TLS records. It never terminates TLS, has no
// certificate, no key and no CA, reads no request and answers none. It can
// drop or delay traffic, as any network part can. Replacing it with socat
// or a load balancer in TCP mode changes nothing about what is trusted.
package forward

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Forwarder copies connections from a listener to the address Dial opens.
type Forwarder struct {
	// Dial opens the connection to the other side, for example transport.Dial
	// to the enclave's vsock address.
	Dial func(ctx context.Context) (net.Conn, error)
	// MaxConns bounds the connections open at once. Zero means 256. A
	// connection over the bound is closed at once.
	MaxConns int
	// DialTimeout bounds Dial. Zero means 5 s.
	DialTimeout time.Duration
	Log         *slog.Logger
}

func (f *Forwarder) maxConns() int {
	if f.MaxConns > 0 {
		return f.MaxConns
	}
	return 256
}

func (f *Forwarder) dialTimeout() time.Duration {
	if f.DialTimeout > 0 {
		return f.DialTimeout
	}
	return 5 * time.Second
}

// Serve accepts connections on l until ctx ends or l fails. On ctx it
// closes l and every open connection, and returns nil.
func (f *Forwarder) Serve(ctx context.Context, l net.Listener) error {
	if f.Log == nil {
		f.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	slots := make(chan struct{}, f.maxConns())
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			f.Log.Warn("too many connections, closing", "remote", c.RemoteAddr().String(), "max", f.maxConns())
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			f.handle(ctx, c)
		}()
	}
}

// closeWriter is a connection that can half-close: TCP, unix and vsock.
type closeWriter interface{ CloseWrite() error }

func (f *Forwarder) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	dctx, cancel := context.WithTimeout(ctx, f.dialTimeout())
	target, err := f.Dial(dctx)
	cancel()
	if err != nil {
		f.Log.Warn("dial failed, closing the client", "remote", client.RemoteAddr().String(), "err", err)
		return
	}
	defer target.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
			target.Close()
		case <-done:
		}
	}()

	// One goroutine per direction. When a direction ends cleanly, pass the
	// half-close on and let the other direction finish; on an error close
	// both.
	res := make(chan error, 2)
	pipe := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if cw, ok := dst.(closeWriter); ok {
				err = cw.CloseWrite()
			} else {
				err = errors.New("no half-close")
			}
		}
		res <- err
	}
	go pipe(target, client)
	go pipe(client, target)
	if err := <-res; err != nil {
		client.Close()
		target.Close()
	}
	<-res
}

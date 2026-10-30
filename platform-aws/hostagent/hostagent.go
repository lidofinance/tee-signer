// Package hostagent is the parent-instance side of a Nitro deployment.
// The enclave has no disk and no network, so the agent on the parent keeps
// the sealed blobs and hands out the instance role credentials the enclave
// needs to call KMS.
//
// Everything the agent does is untrusted: it can drop, replay or roll back
// blobs and withhold credentials. Blobs are sealed by the enclave, so it
// cannot read or forge them. Rollback is why the runner uses the restart
// floor on Nitro.
//
// The client inside the enclave is package agentclient and the messages
// are in package agentwire (the protocol is described there). The runner
// links those two only.
package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform-aws/hostagent/agentwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// Server serves a store and, optionally, credentials.
type Server struct {
	Store platform.Store
	Creds func(ctx context.Context) (agentwire.Credentials, error) // nil: CREDS unsupported
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
	var req agentwire.Request
	if len(f.Payload) > 0 {
		if err := json.Unmarshal(f.Payload, &req); err != nil {
			return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
		}
	}
	var resp any = agentwire.Response{}
	switch f.Type {
	case agentwire.TypeGet:
		v, err := s.Store.Get(req.Key)
		if errors.Is(err, platform.ErrNotFound) {
			return nil, &backend.RefusedError{Code: agentwire.StatusNotFound, Detail: req.Key}
		}
		if err != nil {
			return nil, err
		}
		resp = agentwire.Response{Value: v}
	case agentwire.TypePut:
		if err := s.Store.Put(req.Key, req.Value); err != nil {
			return nil, err
		}
	case agentwire.TypeList:
		keys, err := s.Store.List(req.Prefix)
		if err != nil {
			return nil, err
		}
		resp = agentwire.Response{Keys: keys}
	case agentwire.TypeCreds:
		if s.Creds == nil {
			return nil, backend.Refused(backend.StatusUnsupported, "no credentials source")
		}
		c, err := s.Creds(ctx)
		if err != nil {
			return nil, err
		}
		resp = c
	case agentwire.TypeExit:
		if s.Exit == nil {
			return nil, backend.Refused(backend.StatusUnsupported, "no exit report sink")
		}
		s.Exit(agentwire.ExitText(req.Text))
	case agentwire.TypeSetup:
		if s.Setup == nil {
			return nil, &backend.RefusedError{Code: agentwire.StatusNotFound, Detail: "no setup"}
		}
		v, err := s.Setup()
		if err != nil {
			return nil, err
		}
		resp = agentwire.Response{Value: v}
	default:
		return nil, backend.Refused(backend.StatusUnsupported, "type %v", f.Type)
	}
	return json.Marshal(resp)
}

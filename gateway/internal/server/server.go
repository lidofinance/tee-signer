// Package server is the HTTP side of the gateway: the Web3Signer eth2
// signing API (upcheck, public key list, sign).
package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/gateway/internal/backend"
	"github.com/lidofinance/tee-signer/gateway/internal/coalesce"
	"github.com/lidofinance/tee-signer/gateway/internal/policy"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// Content types exactly as Web3Signer sends them (ContentTypes.java).
const (
	contentTypeJSON = "application/json; charset=utf-8"
	contentTypeText = "text/plain; charset=utf-8"
)

const maxBodyBytes = 10 << 20

// Verifier checks a signature over a signing root.
type Verifier func(pubkey phase0.BLSPubKey, root phase0.Root, sig phase0.BLSSignature) error

// Server handles the Web3Signer eth2 API.
type Server struct {
	signer      backend.Signer
	policy      *policy.Policy
	chain       signing.Chain
	log         *slog.Logger
	signTimeout time.Duration
	verify      Verifier
	// shared is nil unless WithCoalescing turned it on.
	shared *coalesce.Group[signed]
}

// signed is the outcome of one call to the signers: the signature, which
// passed the server's own check when it has a Verifier, and how long the
// call took.
type signed struct {
	sig  phase0.BLSSignature
	took time.Duration
}

// unverifiedError is a signature that failed the server's own check.
type unverifiedError struct{ err error }

func (e *unverifiedError) Error() string { return e.err.Error() }

// New builds a Server.
func New(signer backend.Signer, pol *policy.Policy, chain signing.Chain, log *slog.Logger, signTimeout time.Duration) *Server {
	if signTimeout == 0 {
		signTimeout = 15 * time.Second
	}

	return &Server{signer: signer, policy: pol, chain: chain, log: log, signTimeout: signTimeout}
}

// WithVerifier makes the server check every signature against the
// validator key and the signing root it computed before returning it. The
// signers backend checks its combined signature itself; this is a second
// check for any other Signer.
func (s *Server) WithVerifier(v Verifier) *Server {
	s.verify = v

	return s
}

// WithCoalescing lets identical requests of the non-slashable types
// (coalesce.Shareable) share one call to the signers: same validator key,
// same signing root, same type. A request that arrives while the call is
// in flight waits for it; one that arrives within keep after it succeeded
// gets the stored signature. Errors are never stored. keep 0 shares calls
// in flight only. Attestations, blocks and every other type always make
// their own call.
func (s *Server) WithCoalescing(keep time.Duration) *Server {
	s.shared = coalesce.New[signed](keep, s.signTimeout)

	return s
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /upcheck", s.upcheck)
	mux.HandleFunc("GET /api/v1/eth2/publicKeys", s.publicKeys)
	mux.HandleFunc("POST /api/v1/eth2/sign/{identifier}", s.sign)

	return mux
}

func (s *Server) upcheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", contentTypeText)
	_, _ = io.WriteString(w, "OK")
}

func (s *Server) publicKeys(w http.ResponseWriter, r *http.Request) {
	keys := s.signer.PublicKeys(r.Context())
	out := make([]string, len(keys))
	for i := range keys {
		out[i] = fmt.Sprintf("%#x", keys[i])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	identifier := r.PathValue("identifier")
	log := s.log.With("identifier", identifier)

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Bad Request")
		return
	}

	// Same order as Web3Signer: body (400), then key (404), then refusals (412).
	job, err := signing.Parse(body, s.chain)
	if err != nil {
		if signing.IsBadRequest(err) {
			log.Info("bad request", "err", err.Error())
			writeError(w, http.StatusBadRequest, "Bad Request")
		} else {
			log.Error("parse failed", "err", err.Error())
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}
	log = log.With("type", job.Type, "signer_call", backend.CallName(job))

	pubkey, ok := parsePubkey(identifier)
	if !ok || !s.signer.HasKey(r.Context(), pubkey) {
		log.Info("unknown public key")
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}

	if err := s.policy.Check(pubkey, job); err != nil {
		log.Warn("refused by policy", "err", err.Error())
		writeError(w, http.StatusPreconditionFailed, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.signTimeout)
	defer cancel()
	t0 := time.Now()
	var (
		res signed
		how = coalesce.Called
	)
	if s.shared != nil && job.Method == signing.MethodGeneric && coalesce.Shareable(job.Type) {
		key := coalesce.Key{Pubkey: pubkey, Root: job.SigningRoot, Type: job.Type}
		res, how, err = s.shared.Do(ctx, key, func(ctx context.Context) (signed, error) { return s.call(ctx, pubkey, job) })
	} else {
		res, err = s.call(ctx, pubkey, job)
	}
	// signer_ms: time from the call to the signers until the combined
	// signature (or the error). Only the request that made the call has
	// it; a request that shared another's call or got a stored signature
	// says so with coalesced=true or cache_hit=true instead.
	var timing []any
	switch how {
	case coalesce.Called:
		took := res.took
		if took == 0 {
			// The request gave up before the shared call returned.
			took = time.Since(t0)
		}
		timing = []any{"signer_ms", fmt.Sprintf("%.1f", float64(took.Microseconds())/1000)}
	case coalesce.Coalesced:
		timing = []any{"coalesced", true}
	case coalesce.Cached:
		timing = []any{"cache_hit", true}
	}
	if err != nil {
		var (
			denied     *backend.DeniedError
			unverified *unverifiedError
		)
		switch {
		case errors.Is(err, backend.ErrUnknownKey):
			writeError(w, http.StatusNotFound, "Not Found")
		case errors.As(err, &denied):
			log.Warn("denied by signers", append([]any{"err", err.Error()}, timing...)...)
			writeError(w, http.StatusPreconditionFailed, "Precondition Failed")
		case errors.As(err, &unverified):
			log.Error("signature does not verify", append([]any{"signing_root", fmt.Sprintf("%#x", job.SigningRoot), "err", err.Error()}, timing...)...)
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
		default:
			log.Error("signing failed", append([]any{"err", err.Error()}, timing...)...)
			writeError(w, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}
	// total_ms: the whole request (parse, signers, signature check) until
	// the reply, which is what the client waited.
	log.Info("signed", append(append([]any{"signing_root", fmt.Sprintf("%#x", job.SigningRoot)}, timing...),
		"total_ms", fmt.Sprintf("%.1f", float64(time.Since(start).Microseconds())/1000))...)

	signature := fmt.Sprintf("%#x", res.sig)
	if acceptsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"signature": signature})
		return
	}
	w.Header().Set("Content-Type", contentTypeText)
	_, _ = io.WriteString(w, signature)
}

// call makes one call to the signers and checks the signature with the
// Verifier, if any. took covers the call, not the check. Only a signature
// that passed the check comes back without an error, so a shared or stored
// result has always been checked.
func (s *Server) call(ctx context.Context, pubkey phase0.BLSPubKey, job *signing.Job) (signed, error) {
	t0 := time.Now()
	sig, err := s.signer.Sign(ctx, pubkey, job)
	took := time.Since(t0)
	if err != nil {
		return signed{took: took}, err
	}
	if s.verify != nil {
		if err := s.verify(pubkey, job.SigningRoot, sig); err != nil {
			return signed{took: took}, &unverifiedError{err: err}
		}
	}

	return signed{sig: sig, took: took}, nil
}

// acceptsJSON mirrors Web3Signer: JSON when any Accept entry is
// application/json or */*, plain text otherwise (also with no Accept header).
func acceptsJSON(r *http.Request) bool {
	for _, header := range r.Header.Values("Accept") {
		for _, part := range strings.Split(header, ",") {
			mt, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if mt == "application/json" || mt == "*/*" {
				return true
			}
		}
	}

	return false
}

// parsePubkey accepts the identifier with or without 0x, in any case, like
// Web3Signer's normaliseIdentifier.
func parsePubkey(identifier string) (phase0.BLSPubKey, bool) {
	var pk phase0.BLSPubKey
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(identifier), "0x"))
	if err != nil || len(b) != len(pk) {
		return pk, false
	}
	copy(pk[:], b)

	return pk, true
}

// writeJSON writes v with no trailing newline, as Vert.x JsonObject.encode() does.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"code":500,"message":"Internal Server Error"}`)
	}
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// writeError renders errors like Web3Signer's JsonErrorHandler: {"code","message"}.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"code": status, "message": message})
}

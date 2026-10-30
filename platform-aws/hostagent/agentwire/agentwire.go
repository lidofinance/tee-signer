// Package agentwire is the message format between the Nitro host agent
// (package hostagent, on the parent instance) and its client in the
// enclave (package agentclient). The runner links this package and
// agentclient, never the agent.
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
// SETUP hands the runner its setup at
// every start, before any KMS call: the binary setup the parent keeps in a
// file (hostagent -setup). It is not secret. A host that hands over other
// bytes gets a runner with another setup_hash; once key release takes
// setup_hash (a later step), that runner gets other keys too.
//
// EXIT carries the runner's fatal error line, the one it prints to stderr
// before it exits. A production enclave has no console, so without it a
// failed start shows only as the enclave going away. The runner sends
// nothing else this way. The agent keeps at most MaxExitText bytes of
// printable ASCII and hands the line to hostagent.Server.Exit (the command
// writes it to a file and its log).
package agentwire

import (
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

const (
	TypeGet   wire.MsgType = 0x41
	TypePut   wire.MsgType = 0x42
	TypeList  wire.MsgType = 0x43
	TypeCreds wire.MsgType = 0x44
	TypeExit  wire.MsgType = 0x45
	TypeSetup wire.MsgType = 0x46

	// StatusNotFound answers GET or SETUP without a value.
	StatusNotFound backend.Status = 1404

	// MaxExitText bounds an EXIT line, on both sides.
	MaxExitText = 2048
)

// Request is the payload of every request type; each type uses its own fields.
type Request struct {
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

// Response is the payload of the answers to GET, LIST and SETUP.
type Response struct {
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

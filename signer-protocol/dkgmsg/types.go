package dkgmsg

import "github.com/lidofinance/tee-signer/signer-protocol/wire"

// Wire message types of key generation (docs/dkg.md). They sit at 0x20 and
// up, apart from the other message types. They live here, not
// in package wire, because the runner links package wire into every build:
// one more file there changes the bytes of a runner built without key
// generation, and the Dirk fork copies wire.go on its own.
const (
	// TypeHello starts a session and returns the runner's attested hello.
	TypeHello wire.MsgType = 0x20
	// TypeDeal takes every hello and returns the runner's deal.
	TypeDeal wire.MsgType = 0x21
	// TypeFinish takes every deal and returns the result and the runner's
	// confirmation.
	TypeFinish wire.MsgType = 0x22
	// TypeCommit takes every confirmation; the runner then keeps its shares.
	TypeCommit wire.MsgType = 0x23
	// TypeAbort ends the session in progress.
	TypeAbort wire.MsgType = 0x24
	// TypeOperator returns the runner's operator key, attested.
	TypeOperator wire.MsgType = 0x25
	// TypeSetupSign signs a setup message (deposit, builder registration,
	// Charon lock hash) for a generated key, after the runner checked the
	// full message against its policy.
	TypeSetupSign wire.MsgType = 0x26
)

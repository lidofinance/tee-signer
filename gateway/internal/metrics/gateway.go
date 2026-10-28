package metrics

import (
	"time"

	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
)

// prefix starts the name of every gateway metric.
const prefix = "teesigner_gateway_"

// The values of the labels with a fixed set. The other labels are signer,
// a name from the config, and type, a Web3Signer request type the gateway
// parsed. No label holds a key or anything a client chooses freely.
var (
	DialResults        = []string{"ok", "failed"}
	AttestationReasons = []string{"tls", "key_pin", "identity", "verifier"}
	SignerResults      = []string{"ok", "refused", "error", "timeout"}
	CombineReasons     = []string{"bad_partial", "below_threshold", "verify"}
)

// signBuckets are the bucket bounds of the signing time, in seconds.
var signBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Gateway is the set of gateway metrics. Every field is safe for
// concurrent use.
type Gateway struct {
	Registry *Registry

	// Per signer (label signer).
	SignerConnectionsUp       *GaugeVec
	SignerDials               *CounterVec // result: DialResults
	SignerRotations           *CounterVec // result: DialResults
	SignerAttestationFailures *CounterVec // reason: AttestationReasons
	SignerRequests            *CounterVec // result: SignerResults
	SignerKeysRefreshed       *GaugeVec

	// Keys is the number of validator keys the gateway signs for.
	Keys *GaugeVec
	// Requests counts sign requests by type and result.
	Requests *CounterVec
	// SignDuration is the time from the fan-out to the combined
	// signature, by type.
	SignDuration *HistogramVec
	// CombineFailures counts failed combinations by reason
	// (CombineReasons).
	CombineFailures *CounterVec
}

// New returns the gateway metrics in a new registry.
func New() *Gateway {
	r := NewRegistry()
	g := &Gateway{
		Registry: r,
		SignerConnectionsUp: r.Gauge(prefix+"signer_connections_up",
			"Connections to the signer that passed every check and have not failed since.", "signer"),
		SignerDials: r.Counter(prefix+"signer_dials_total",
			"New connections to the signer, by result: ok passed every check, failed did not.", "signer", "result"),
		SignerRotations: r.Counter(prefix+"signer_rotations_total",
			"Connections moved to a new client certificate, by result.", "signer", "result"),
		SignerAttestationFailures: r.Counter(prefix+"signer_attestation_failures_total",
			"New connections the signer checks refused, by the check: tls (handshake, build flavour, chain mark), "+
				"key_pin, identity (IDENTITY, nonce, TLS key binding), verifier (attestation document, setup pins).",
			"signer", "reason"),
		SignerRequests: r.Counter(prefix+"signer_requests_total",
			"Calls to the signer (SIGN and PUBLIC_KEYS), by result.", "signer", "result"),
		SignerKeysRefreshed: r.Gauge(prefix+"signer_keys_refreshed_timestamp_seconds",
			"Unix time of the last key list the signer answered.", "signer"),
		Keys: r.Gauge(prefix+"keys", "Validator keys the gateway signs for."),
		Requests: r.Counter(prefix+"requests_total",
			"Sign requests whose body parsed, by type and result: ok, unknown_key, policy, denied, error, timeout.",
			"type", "result"),
		SignDuration: r.Histogram(prefix+"sign_duration_seconds",
			"Time from sending a request to the signers to the combined signature, for requests that signed.",
			signBuckets, "type"),
		CombineFailures: r.Counter(prefix+"combine_failures_total",
			"Partial signatures that do not verify (bad_partial), requests with too few good partial signatures "+
				"(below_threshold), and combined signatures that do not verify (verify).", "reason"),
	}
	g.Keys.Set(0)
	for _, reason := range CombineReasons {
		g.CombineFailures.Add(0, reason)
	}

	return g
}

// Signer makes the series of the signer name with 0, so that they exist
// before the first event.
func (g *Gateway) Signer(name string) {
	g.SignerConnectionsUp.Set(0, name)
	g.SignerKeysRefreshed.Set(0, name)
	for _, r := range DialResults {
		g.SignerDials.Add(0, name, r)
		g.SignerRotations.Add(0, name, r)
	}
	for _, r := range AttestationReasons {
		g.SignerAttestationFailures.Add(0, name, r)
	}
	for _, r := range SignerResults {
		g.SignerRequests.Add(0, name, r)
	}
}

// CertSource is the client certificate in force and the reload counts
// (certreload.Watcher).
type CertSource interface {
	Current() *certreload.Pair
	Stats() certreload.Stats
}

// Certs adds the client certificate metrics, read from w at each scrape.
func (g *Gateway) Certs(w CertSource) {
	r := g.Registry
	r.Func(prefix+"client_cert_not_after_seconds", "Unix time the client certificate in force expires.", "gauge", nil,
		func(emit func(float64, ...string)) { emit(unix(w.Current().NotAfter())) })
	r.Func(prefix+"client_cert_not_before_seconds", "Unix time the client certificate in force became valid.", "gauge", nil,
		func(emit func(float64, ...string)) { emit(unix(w.Current().NotBefore())) })
	r.Func(prefix+"client_cert_reloads_total",
		"Reads of the client certificate files, by result: ok swapped in a new pair, refused kept the pair in force, "+
			"unchanged found the pair in force.", "counter", []string{"result"},
		func(emit func(float64, ...string)) {
			s := w.Stats()
			emit(float64(s.Reloaded), "ok")
			emit(float64(s.Refused), "refused")
			emit(float64(s.Unchanged), "unchanged")
		})
	r.Func(prefix+"client_cert_last_reload_timestamp_seconds",
		"Unix time the client certificate in force took effect: the start, or the last successful reload.", "gauge", nil,
		func(emit func(float64, ...string)) { emit(unix(w.Stats().Since)) })
}

func unix(t time.Time) float64 { return float64(t.Unix()) + float64(t.Nanosecond())/1e9 }

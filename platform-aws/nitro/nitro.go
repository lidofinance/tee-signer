// Package nitro is the AWS Nitro Enclaves platform. UNTESTED: it compiles
// and its parsers have unit tests, but no part ran inside an enclave.
//
// Flows (sources in cloud/aws/README.md):
//
//   - Attestation: NSM attestation document from /dev/nsm (hf/nsm), with
//     the runner's user data and the client's nonce.
//   - Sealing: an AES-256 data key from KMS. First boot: GenerateDataKey
//     with Recipient = attestation document carrying a fresh RSA-2048 key;
//     KMS returns the key encrypted to that RSA key (CMS, see cms.go) and
//     the KMS ciphertext blob, which goes to the host store. Later boots:
//     Decrypt(blob, Recipient). The key policy allows this only for the
//     measured image (PCR0/1/2 conditions), see cloud/aws/kms-key-policy.json.
//     platform.Keys (the mark log's keys) is GenerateDataKey and Decrypt
//     with an encryption context, the ciphertext kept by the caller. Every
//     call carries setup_hash in its encryption context (Keys).
//   - Store: the host agent on the parent (package hostagent), over vsock.
//     The parent can roll it back; use the restart floor.
//   - Network: none. HTTPS to KMS (and to time sources) goes through
//     vsock-proxy on the parent: one vsock port per host:port.
//   - Way in: the runner listens on vsock and serves mutual TLS 1.3 there
//     (package attls, -tls-client-ca, required on this platform). The parent
//     is not trusted. It forwards bytes (runner/cmd/forwarder) and has no
//     client certificate. The TLS key is made in the enclave and its hash
//     is in the identity, which the NSM document covers.
//   - Clock: the enclave's system clock is set by the host. Options are
//     clock=system (default, untrusted), clock=nsm (NSM timestamps, open
//     question), or the NTS clock of a runner built with the tag nts (-nts-clock, the release
//     image's choice): NTS-KE through vsock-proxy routes for port 4460 and
//     NTP through the parent's UDP relay (ntp_relay, runner/udprelay).
package nitro

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform-aws/hostagent/agentclient"
	"github.com/lidofinance/tee-signer/platform-aws/udprelay"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

const dataKeyBlob = "sealing/datakey.kms"

// ProxyClient returns an HTTP client whose connections to each host:port
// in routes go to the given vsock (or other transport) address, where
// vsock-proxy forwards them. TLS still runs end to end inside the enclave.
func ProxyClient(routes map[string]transport.Addr) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			a, ok := routes[addr]
			if !ok {
				return nil, fmt.Errorf("nitro: no vsock-proxy route for %s", addr)
			}
			return transport.Dial(ctx, a)
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// ParseRoutes parses "host:port=vsock:3:8000,host2:443=vsock:3:8001".
func ParseRoutes(s string) (map[string]transport.Addr, error) {
	routes := map[string]transport.Addr{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		hostport, addr, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("nitro: proxy route %q: want host:port=addr", part)
		}
		a, err := transport.Parse(addr)
		if err != nil {
			return nil, err
		}
		routes[hostport] = a
	}
	return routes, nil
}

// NetDial is the NTS clock's dialer in the enclave (platform.Platform.Dial):
// TCP to a host:port of routes, which vsock-proxy forwards (NTS-KE, port
// 4460), and UDP through the relay on the parent (NTP, package udprelay).
// Neither is trusted: TLS and the NTS authenticator run end to end inside
// the enclave, so the parent can delay or drop but not change an answer.
func NetDial(routes map[string]transport.Addr, relay *transport.Addr) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp":
			a, ok := routes[addr]
			if !ok {
				return nil, fmt.Errorf("nitro: no vsock-proxy route for %s", addr)
			}
			return transport.Dial(ctx, a)
		case "udp":
			if relay == nil {
				return nil, fmt.Errorf("nitro: no UDP relay for %s (platform option ntp_relay)", addr)
			}
			c, err := udprelay.Dial(ctx, *relay, addr)
			if err != nil {
				return nil, err
			}
			return c, nil
		}
		return nil, fmt.Errorf("nitro: cannot dial %s %s", network, addr)
	}
}

// netOptions reads the proxy routes and the UDP relay from the options.
func netOptions(o platform.Options) (map[string]transport.Addr, *transport.Addr, error) {
	routes, err := ParseRoutes(o.Param("proxy", ""))
	if err != nil {
		return nil, nil, err
	}
	s := o.Param("ntp_relay", "")
	if s == "" {
		return routes, nil, nil
	}
	relay, err := transport.Parse(s)
	if err != nil {
		return nil, nil, fmt.Errorf("nitro: ntp_relay: %w", err)
	}
	return routes, &relay, nil
}

type agentCreds struct{ c *agentclient.Client }

func (a agentCreds) Retrieve(ctx context.Context) (aws.Credentials, error) {
	cr, err := a.c.Credentials(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}
	return aws.Credentials{AccessKeyID: cr.AccessKeyID, SecretAccessKey: cr.SecretAccessKey,
		SessionToken: cr.SessionToken, CanExpire: !cr.Expiration.IsZero(), Expires: cr.Expiration,
		Source: "nitro-host-agent"}, nil
}

// kmsRecipient makes a fresh RSA key and an NSM document that carries it,
// so KMS encrypts its answer to this enclave only. seen records the
// document's PCR0 to PCR2: the image the key policy let have the key.
func kmsRecipient(n *NSM, seen *platform.ImageSeen) (*rsa.PrivateKey, *types.RecipientInfo, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	doc, err := n.Document(nil, []byte("signer-runner kms recipient"), pub)
	if err != nil {
		return nil, nil, err
	}
	seen.Record(documentImage(doc))
	return rsaKey, &types.RecipientInfo{AttestationDocument: doc,
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256}, nil
}

// The encryption contexts of the KMS calls:
//
//	sealing data key     {purpose: sealing, signer-setup: <setup_hash, hex>}
//	platform.Keys        {signer-key: <aad, hex>, signer-setup: <setup_hash, hex>}
//	record credentials   {purpose: record-creds}
//
// The runner's own keys carry setup_hash, so a runner of the same image
// with another setup, even under the same KMS key, decrypts none of them.
// The key policy (cloud/aws/kms-key-policy.json.tmpl, main.tf) lets the key
// admin call Encrypt with exactly {purpose: record-creds} and nothing else,
// so no blob the admin makes decrypts under the other two: the admin cannot
// plant a sealing key or a mark log key. Only GenerateDataKey with this
// enclave's attestation as recipient makes those. KMS takes strings, so
// the binary values go in hex: the SDK turns bytes that are not UTF-8 into
// U+FFFD, which would drop most of a hash.
const (
	ctxPurpose         = "purpose"
	ctxSetup           = "signer-setup"
	keyContext         = "signer-key"
	purposeSealing     = "sealing"
	purposeRecordCreds = "record-creds"
)

// recordCredsContext is the context the key admin encrypts the record
// credentials under: `aws kms encrypt --encryption-context
// purpose=record-creds` (cloud/aws/README.md).
func recordCredsContext() map[string]string { return map[string]string{ctxPurpose: purposeRecordCreds} }

// notAuthentic reports whether KMS refused a ciphertext as not its own:
// made under another key or context, or not by KMS
// (InvalidCiphertextException, IncorrectKeyException for another key).
func notAuthentic(err error) bool {
	var bad *types.InvalidCiphertextException
	var other *types.IncorrectKeyException
	return errors.As(err, &bad) || errors.As(err, &other)
}

// Keys holds the runner's KMS calls: the sealing data key, the record
// credentials, and platform.Keys (GenerateDataKey with the aad and
// setup_hash as encryption context and the enclave as recipient, Decrypt
// with the same context). The key policy allows GenerateDataKey and
// Decrypt to the measured image only, and Encrypt to the key admin only
// with the record credentials' context, so a key blob that decrypts was
// made inside an enclave of that image with this setup.
type Keys struct {
	Client    *kms.Client
	KeyID     string
	Recipient func() (*rsa.PrivateKey, *types.RecipientInfo, error)
	// Setup is setup_hash, in the context of every call but the record
	// credentials'. Zero on the flag path.
	Setup [32]byte
}

func (k Keys) setupHex() string { return hex.EncodeToString(k.Setup[:]) }

// KeyRule reads the rule of the KMS key (platform.KeyRule): its metadata
// (DescribeKey) and its key policy (GetKeyPolicy, policy "default"), so a
// verifier sees whether the policy that guards the sealing key is locked,
// whether the key material came from outside KMS (Origin) and whether
// replicas in other regions exist (MultiRegion). key_release_hash is over,
// in order: Arn, Origin, KeyManager, MultiRegion (one byte) and the policy
// text as KMS returns it. The lock is policyLock of the same answers. The
// key policy grants the parent role these two reads
// (cloud/aws/kms-key-policy.json.tmpl). The answers come over TLS from KMS,
// so the parent cannot change them. UNTESTED against KMS: the code ran
// against a fake.
func (k Keys) KeyRule(ctx context.Context) (platform.KeyRule, error) {
	d, err := k.Client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(k.KeyID)})
	if err != nil {
		return platform.KeyRule{}, fmt.Errorf("nitro: DescribeKey: %w", err)
	}
	m := d.KeyMetadata
	if m == nil || m.Arn == nil || m.MultiRegion == nil || m.Origin == "" || m.KeyManager == "" {
		return platform.KeyRule{}, errors.New("nitro: DescribeKey answer lacks Arn, Origin, KeyManager or MultiRegion")
	}
	p, err := k.Client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: aws.String(k.KeyID), PolicyName: aws.String("default")})
	if err != nil {
		return platform.KeyRule{}, fmt.Errorf("nitro: GetKeyPolicy: %w", err)
	}
	if p.Policy == nil || *p.Policy == "" {
		return platform.KeyRule{}, errors.New("nitro: GetKeyPolicy answer has no policy")
	}
	multi := byte(0)
	if *m.MultiRegion {
		multi = 1
	}
	r := platform.KeyRule{Hash: backend.KeyReleaseHash(backend.KeyReleaseNitro, []byte(*m.Arn), []byte(m.Origin), []byte(m.KeyManager),
		[]byte{multi}, []byte(*p.Policy))}
	r.Lock, r.Why = policyLock(*p.Policy, string(m.Origin), *m.MultiRegion)
	return r, nil
}

func (k Keys) sealingContext() map[string]string {
	return map[string]string{ctxPurpose: purposeSealing, ctxSetup: k.setupHex()}
}

func (k Keys) keyContext(aad []byte) map[string]string {
	return map[string]string{keyContext: hex.EncodeToString(aad), ctxSetup: k.setupHex()}
}

// recordCredentials decrypts the DynamoDB or S3 writer credentials inside
// the enclave. The blob under key in the host store (the images use
// record/writer-credentials.kms) is JSON {"access_key_id",
// "secret_access_key"} that the key admin encrypted with `aws kms encrypt
// --encryption-context purpose=record-creds` under the enclave's KMS key.
// The key policy lets only the measured enclave decrypt, so the parent
// never sees the credentials and cannot write the record itself.
// UNTESTED: needs an enclave and KMS.
func (k Keys) recordCredentials(ctx context.Context, store platform.Store, key string) (platform.Credentials, error) {
	blob, err := store.Get(key)
	if err != nil {
		return platform.Credentials{}, fmt.Errorf("nitro: record credentials %s: %w", key, err)
	}
	rsaKey, recipient, err := k.Recipient()
	if err != nil {
		return platform.Credentials{}, err
	}
	out, err := k.Client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(k.KeyID), CiphertextBlob: blob,
		EncryptionContext: recordCredsContext(), Recipient: recipient})
	if err != nil {
		return platform.Credentials{}, fmt.Errorf("nitro: kms Decrypt (record credentials, encrypted with the context purpose=record-creds?): %w", err)
	}
	plain, err := DecryptEnvelopedData(out.CiphertextForRecipient, rsaKey)
	if err != nil {
		return platform.Credentials{}, err
	}
	defer clear(plain)
	var c struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if err := json.Unmarshal(plain, &c); err != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return platform.Credentials{}, errors.New("nitro: record credentials: want JSON with access_key_id and secret_access_key")
	}
	return platform.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey}, nil
}

// dataKey gets the sealing key under the sealing context of this setup:
// from the stored blob with Decrypt, or a new one with GenerateDataKey on
// first boot. A stored blob of another setup or KMS key, or one the key
// admin made, does not decrypt, and the start stops.
func (k Keys) dataKey(ctx context.Context, store platform.Store) ([]byte, error) {
	rsaKey, recipient, err := k.Recipient()
	if err != nil {
		return nil, err
	}

	blob, err := store.Get(dataKeyBlob)
	switch {
	case errors.Is(err, platform.ErrNotFound):
		out, err := k.Client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId: aws.String(k.KeyID), KeySpec: types.DataKeySpecAes256, EncryptionContext: k.sealingContext(), Recipient: recipient})
		if err != nil {
			return nil, fmt.Errorf("nitro: kms GenerateDataKey: %w", err)
		}
		if err := store.Put(dataKeyBlob, out.CiphertextBlob); err != nil {
			return nil, err
		}
		return DecryptEnvelopedData(out.CiphertextForRecipient, rsaKey)
	case err != nil:
		return nil, err
	}
	out, err := k.Client.Decrypt(ctx, &kms.DecryptInput{
		KeyId: aws.String(k.KeyID), CiphertextBlob: blob, EncryptionContext: k.sealingContext(), Recipient: recipient})
	if notAuthentic(err) {
		return nil, fmt.Errorf("nitro: the stored sealing key %s does not decrypt under this KMS key and setup_hash %x: "+
			"it belongs to another setup or key, or the host put it there; a new setup starts on an empty store (%v)", dataKeyBlob, k.Setup, err)
	}
	if err != nil {
		return nil, fmt.Errorf("nitro: kms Decrypt: %w", err)
	}
	return DecryptEnvelopedData(out.CiphertextForRecipient, rsaKey)
}

func (k Keys) NewKey(ctx context.Context, aad []byte) ([]byte, []byte, error) {
	rsaKey, recipient, err := k.Recipient()
	if err != nil {
		return nil, nil, err
	}
	out, err := k.Client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{KeyId: aws.String(k.KeyID), KeySpec: types.DataKeySpecAes256,
		EncryptionContext: k.keyContext(aad), Recipient: recipient})
	if err != nil {
		return nil, nil, fmt.Errorf("nitro: kms GenerateDataKey (wrapped key): %w", err)
	}
	key, err := DecryptEnvelopedData(out.CiphertextForRecipient, rsaKey)
	if err != nil {
		return nil, nil, err
	}
	return key, out.CiphertextBlob, nil
}

// OpenKey: KMS refuses a ciphertext it did not make, under another key or
// with another context with InvalidCiphertextException (IncorrectKeyException
// for another key); those are ErrNotAuthentic. Other failures (access
// denied, throttling, network) are returned as they are.
func (k Keys) OpenKey(ctx context.Context, blob, aad []byte) ([]byte, error) {
	rsaKey, recipient, err := k.Recipient()
	if err != nil {
		return nil, err
	}
	out, err := k.Client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(k.KeyID), CiphertextBlob: blob,
		EncryptionContext: k.keyContext(aad), Recipient: recipient})
	if notAuthentic(err) {
		return nil, fmt.Errorf("%w (%v)", platform.ErrNotAuthentic, err)
	}
	if err != nil {
		return nil, fmt.Errorf("nitro: kms Decrypt (wrapped key): %w", err)
	}
	key, err := DecryptEnvelopedData(out.CiphertextForRecipient, rsaKey)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, platform.ErrNotAuthentic
	}
	return key, nil
}

// New builds the platform. Params:
//
//	agent=vsock:3:7101                       host agent (store + credentials)
//	region=eu-west-1                         KMS region
//	kms_key_id=arn:aws:kms:...               key whose policy checks the PCRs
//	proxy=kms.eu-west-1.amazonaws.com:443=vsock:3:8000[,host:port=addr...]
//	                                         also the NTS-KE hosts, port 4460
//	ntp_relay=vsock:3:7102                   the UDP relay on the parent, for
//	                                         the NTS clock's NTP (udprelay)
//	clock=system|nsm
//	record_creds=record/writer-credentials.kms   store key of the clone
//	                                             guard's KMS-encrypted credentials
func New(o platform.Options) (*platform.Platform, error) {
	if p, ok, err := debugPlatform(o); ok || err != nil {
		return p, err
	}
	n, err := OpenNSM()
	if err != nil {
		return nil, err
	}
	agent, err := agentclient.NewClient(o.Param("agent", "vsock:3:7101"))
	if err != nil {
		n.Close()
		return nil, err
	}
	// From here a failure also goes to the host agent: the runner exits
	// right after, and a production enclave has no console. The line is
	// the one the runner prints (main.go).
	fail := func(err error) (*platform.Platform, error) {
		_ = agent.ReportExit("runner: platform nitro: " + err.Error())
		n.Close()
		return nil, err
	}

	routes, relay, err := netOptions(o)
	if err != nil {
		return fail(err)
	}
	httpClient := ProxyClient(routes)
	region, keyID := o.Param("region", ""), o.Param("kms_key_id", "")
	if region == "" || keyID == "" {
		return fail(errors.New("nitro: region and kms_key_id are required"))
	}
	client := kms.New(kms.Options{Region: region, Credentials: agentCreds{agent}, HTTPClient: httpClient})
	seen := &platform.ImageSeen{}
	keys := Keys{Client: client, KeyID: keyID, Setup: o.SetupHash,
		Recipient: func() (*rsa.PrivateKey, *types.RecipientInfo, error) { return kmsRecipient(n, seen) }}

	// key_release_hash and the lock, read before the sealing key is made or
	// opened. On mainnet a key policy someone can still change stops the
	// start here.
	rule, err := o.ReadKeyRule(context.Background(), keys.KeyRule)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key, err := keys.dataKey(ctx, agent)
	if err != nil {
		return fail(err)
	}
	sealer, err := platform.NewGCMSealer(key)
	clear(key)
	if err != nil {
		return fail(err)
	}

	var clk platform.Clock = clock.System{}
	switch o.Param("clock", "system") {
	case "system":
	case "nsm":
		clk = &clock.Anchored{Src: NSMTime{NSM: n}, Interval: clock.DefaultInterval, TrustedSrc: false}
	default:
		return fail(fmt.Errorf("nitro: unknown clock %q", o.Param("clock", "")))
	}
	plat := &platform.Platform{
		Name:       "nitro",
		Sealer:     sealer,
		Store:      agent,
		Clock:      clk,
		Attester:   n,
		HTTPClient: httpClient,
		Dial:       NetDial(routes, relay),
		Close:      n.Close,
		ReportExit: func(text string) { _ = agent.ReportExit(text) },
		Keys:       keys,
		KeyRule:    rule,
		// PCR0 to PCR2 of the documents KMS took as recipient.
		SelfImage: seen.Get,
	}
	if key := o.Param("record_creds", ""); key != "" {
		creds, err := keys.recordCredentials(ctx, agent, key)
		if err != nil {
			return fail(err)
		}
		plat.RecordCredentials = func(context.Context) (platform.Credentials, error) { return creds, nil }
	}
	return plat, nil
}

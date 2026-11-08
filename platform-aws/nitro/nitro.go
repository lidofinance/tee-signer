// Package nitro is the AWS Nitro Enclaves platform. UNTESTED: it compiles
// and its parsers have unit tests, but no part ran inside an enclave.
//
// Flows (sources in platform-aws/deploy/README.md):
//
//   - Attestation: NSM attestation document from /dev/nsm (hf/nsm), with
//     the runner's user data and the client's nonce.
//   - Sealing: an AES-256 data key from KMS. First boot: GenerateDataKey
//     with Recipient = attestation document carrying a fresh RSA-2048 key;
//     KMS returns the key encrypted to that RSA key (CMS, see cms.go) and
//     the KMS ciphertext blob, which goes to the host store. Later boots:
//     Decrypt(blob, Recipient). The key policy allows this only for the
//     measured image (PCR0/1/2 conditions), see platform-aws/deploy/kms-key-policy.json.tmpl.
//     platform.Keys (the mark log's keys) is GenerateDataKey and Decrypt
//     with an encryption context, the ciphertext kept by the caller. Every
//     call carries setup_hash in its encryption context (Keys).
//   - Store: the host agent on the parent (package hostagent), over vsock.
//     The parent can roll it back; use the restart floor.
//   - Network: none. HTTPS to KMS (and to time sources) goes through
//     vsock-proxy on the parent: one vsock port per host:port.
//   - Way in: the runner listens on vsock and serves mutual TLS 1.3 there
//     (package attls, -tls-client-ca, required on this platform). The parent
//     is not trusted. It forwards bytes (platform-aws/cmd/forwarder) and has no
//     client certificate. The TLS key is made in the enclave and its hash
//     is in the identity, which the NSM document covers.
//   - Clock: the enclave's system clock is set by the host. Options are
//     clock=system (default, untrusted), or the NTS clock of a runner built
//     with the tag nts (-nts-clock, the release image's choice): NTS-KE
//     through vsock-proxy routes for port 4460 and NTP through the parent's
//     UDP relay (ntp_relay, package relayclient).
package nitro

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform-aws/hostagent/agentclient"
	"github.com/lidofinance/tee-signer/platform-aws/udprelay/relayclient"
	"github.com/lidofinance/tee-signer/platform/cloudroots"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

const dataKeyBlob = "sealing/datakey.kms"

// sharePrefix is where the runner stores its sealed shares
// (tee-signer/server ListShares).
const sharePrefix = "shares/"

// ProxyClient returns an HTTP client whose connections to each host:port
// in routes go to the given vsock (or other transport) address, where
// vsock-proxy forwards them. TLS still runs end to end inside the enclave,
// and trusts AWS's roots only (cloudroots).
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
		TLSClientConfig:     &tls.Config{RootCAs: cloudroots.Pool(cloudroots.AWS)},
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
// 4460), and UDP through the relay on the parent (NTP, package relayclient).
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
			c, err := relayclient.Dial(ctx, *relay, addr)
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
// The key policy (platform-aws/deploy/kms-key-policy.json.tmpl, main.tf) lets the key
// admin call Encrypt with exactly {purpose: record-creds} and nothing else,
// so no blob the admin makes decrypts under the other two: the admin cannot
// plant a sealing key or a mark log key. Only GenerateDataKey with this
// enclave's attestation as recipient makes those. That holds once the
// policy is locked: before, the admin holds PutKeyPolicy and can allow
// itself more, so dataKey does not trust a sealing blob on a store without
// shares (AWS-KMS-02). KMS takes strings, so
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
// purpose=record-creds` (platform-aws/deploy/README.md).
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
	// CreationDate is the setup's sealing_key_release.kms_key_creation_date
	// in Unix seconds; 0 when the setup has none (off prod only).
	CreationDate int64
}

func (k Keys) setupHex() string { return hex.EncodeToString(k.Setup[:]) }

// KeyRule reads the rule of the KMS key (platform.KeyRule): its metadata
// (DescribeKey) and its key policy (GetKeyPolicy, policy "default"), so a
// verifier sees whether the policy that guards the sealing key is locked,
// whether the key material came from outside KMS (Origin) and whether
// replicas in other regions exist (MultiRegion). key_release_hash is over,
// in order: Arn, Origin, KeyManager, MultiRegion (one byte) and the policy
// in canonical form (backend.CanonicalJSON): KMS returns the members of an
// object in varying order, so the text it returns differs between reads of
// one policy. A policy that does not parse is an error. The lock is
// policyLock of the same answers, and then grantLock of the key's grants
// (ListGrants, every page): a key with
// a listed grant is not locked, so the hash of a locked key, which leaves
// the grants out, describes everything that releases it as far as
// ListGrants shows (grantLock: a grant made shortly before the read may
// not be listed yet). A ListGrants that fails gives KeyLockUnread and a
// zero hash, as every other failed read does. The key policy grants the
// parent role these three reads
// (platform-aws/deploy/kms-key-policy.json.tmpl). The answers come over TLS from KMS,
// so the parent cannot change them. UNTESTED against KMS: the code ran
// against a fake.
//
// k.KeyID must be a key ARN or an alias ARN in the client's region
// (checkKeyID): a bare key ID or alias resolves in the account of the
// credentials, which the parent supplies. The key DescribeKey answers must
// be in the account and region of that ARN, and be that key for a key ARN;
// otherwise KeyRule returns an error that wraps errWrongKey. KeyRule also
// returns the key's ARN. Every later call (GetKeyPolicy, ListGrants,
// Decrypt, GenerateDataKey) must name the key by it: GetKeyPolicy and
// ListGrants take no alias, and an alias can be pointed at another key
// after the check (readKeyRule).
func (k Keys) KeyRule(ctx context.Context) (platform.KeyRule, string, error) {
	want, err := checkKeyID(k.KeyID, k.Client.Options().Region)
	if err != nil {
		return platform.KeyRule{}, "", err
	}
	d, err := k.Client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(k.KeyID)})
	if err != nil {
		return platform.KeyRule{}, "", fmt.Errorf("nitro: DescribeKey: %w", err)
	}
	m := d.KeyMetadata
	if m == nil || m.Arn == nil || m.MultiRegion == nil || m.Origin == "" || m.KeyManager == "" {
		return platform.KeyRule{}, "", errors.New("nitro: DescribeKey answer lacks Arn, Origin, KeyManager or MultiRegion")
	}
	arn := *m.Arn
	got, err := parseKeyARN(arn)
	switch {
	case err != nil || got.resource != "key":
		return platform.KeyRule{}, "", fmt.Errorf("%w: DescribeKey of %s answered %q, not a key ARN", errWrongKey, k.KeyID, arn)
	case got.partition != want.partition || got.region != want.region || got.account != want.account:
		return platform.KeyRule{}, "", fmt.Errorf("%w: %s resolves to %s, outside account %s in %s", errWrongKey, k.KeyID, arn, want.account, want.region)
	case want.resource == "key" && arn != k.KeyID:
		return platform.KeyRule{}, "", fmt.Errorf("%w: DescribeKey of %s answered %s", errWrongKey, k.KeyID, arn)
	}
	// AWS-KMS-02: the approvers checked in CloudTrail that the key with
	// this creation date was created locked. A key locked after a mutable
	// phase, or another key under the alias, has another date.
	if k.CreationDate != 0 && (m.CreationDate == nil || m.CreationDate.Unix() != k.CreationDate) {
		return platform.KeyRule{}, "", fmt.Errorf("%w: %s has CreationDate %s, the setup pins kms_key_creation_date %s",
			errWrongKey, arn, aws.ToTime(m.CreationDate).UTC().Format(time.RFC3339), time.Unix(k.CreationDate, 0).UTC().Format(time.RFC3339))
	}
	p, err := k.Client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: aws.String(arn), PolicyName: aws.String("default")})
	if err != nil {
		return platform.KeyRule{}, arn, fmt.Errorf("nitro: GetKeyPolicy: %w", err)
	}
	if p.Policy == nil || *p.Policy == "" {
		return platform.KeyRule{}, arn, errors.New("nitro: GetKeyPolicy answer has no policy")
	}
	canon, err := backend.CanonicalJSON([]byte(*p.Policy))
	if err != nil {
		return platform.KeyRule{}, arn, fmt.Errorf("nitro: GetKeyPolicy answer: %w", err)
	}
	multi := byte(0)
	if *m.MultiRegion {
		multi = 1
	}
	r := platform.KeyRule{Hash: backend.KeyReleaseHash(backend.KeyReleaseNitro, []byte(arn), []byte(m.Origin), []byte(m.KeyManager),
		[]byte{multi}, canon)}
	r.Lock, r.Why = policyLock(*p.Policy, string(m.Origin), *m.MultiRegion)
	if r.Lock != backend.KeyLockLocked {
		return r, arn, nil
	}
	grants, err := listGrants(ctx, k.Client, arn)
	if err != nil {
		// The hash leaves the grants out, so it must not stand for a rule
		// whose grants are unknown.
		return platform.KeyRule{Lock: backend.KeyLockUnread, Why: fmt.Sprintf("nitro: ListGrants: %v", err)}, arn, nil
	}
	if r.Lock, r.Why = grantLock(grants); r.Lock == backend.KeyLockLocked {
		// The images the locked policy releases the key to, for the
		// runner's compare with allowed_image_measurements in force. A
		// rule that is not locked reports no image set (platform.KeyRule).
		r.Images = policyImages(*p.Policy)
	}
	return r, arn, nil
}

// errWrongKey marks a kms_key_id that is not a key or alias ARN of the
// client's region, or one that resolves to a key outside the account and
// region of that ARN. readKeyRule stops the start on it on every chain:
// unlike a missing read grant, it points the runner at a key the setup
// does not name.
var errWrongKey = errors.New("nitro: kms_key_id")

// keyARN is a KMS key or alias ARN: arn:PARTITION:kms:REGION:ACCOUNT:key/ID
// or :alias/NAME.
type keyARN struct{ partition, region, account, resource string }

var keyARNRE = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):([0-9]{12}):(key|alias)/[A-Za-z0-9/_-]+$`)

func parseKeyARN(s string) (keyARN, error) {
	m := keyARNRE.FindStringSubmatch(s)
	if m == nil {
		return keyARN{}, fmt.Errorf("%q is not a KMS key or alias ARN", s)
	}
	return keyARN{partition: m[1], region: m[2], account: m[3], resource: m[4]}, nil
}

// checkKeyID parses kms_key_id as a key or alias ARN in region.
func checkKeyID(id, region string) (keyARN, error) {
	a, err := parseKeyARN(id)
	if err != nil {
		return keyARN{}, fmt.Errorf("%w: %v; a bare key ID or alias resolves in the account of the parent's credentials", errWrongKey, err)
	}
	if a.region != region {
		return keyARN{}, fmt.Errorf("%w: %s is in region %s, not %s", errWrongKey, id, a.region, region)
	}
	return a, nil
}

// readKeyRule reads the key rule under the mainnet rule of o
// (platform.Options.ReadKeyRule) and returns it with the key ID every
// later call uses: the ARN DescribeKey answered, or keys.KeyID when the
// read did not get that far or did not run (the flag path). A kms_key_id
// that errWrongKey refuses stops the start on every chain, and so does a
// pinned kms_key_creation_date that the read could not compare.
func readKeyRule(ctx context.Context, o platform.Options, keys Keys) (*platform.KeyRule, string, error) {
	id := keys.KeyID
	var wrong error
	rule, err := o.ReadKeyRule(ctx, func(ctx context.Context) (platform.KeyRule, error) {
		r, arn, err := keys.KeyRule(ctx)
		if errors.Is(err, errWrongKey) {
			wrong = err
		}
		// arn is set only once the creation date compare has passed. An
		// error before it leaves a pinned date unchecked, and that must
		// stop the start off prod too, not count as an unread rule.
		if err != nil && arn == "" && keys.CreationDate != 0 && wrong == nil {
			wrong = fmt.Errorf("%w: kms_key_creation_date is pinned but DescribeKey gave no answer to compare: %v", errWrongKey, err)
		}
		if arn != "" {
			id = arn
		}
		return r, err
	})
	if wrong != nil {
		return nil, "", wrong
	}
	if err != nil {
		return nil, "", err
	}
	return rule, id, nil
}

// listGrants reads every grant of the key arn, all pages of ListGrants. A
// page that says Truncated without a new NextMarker is an error, not the
// end of the list.
func listGrants(ctx context.Context, c *kms.Client, arn string) ([]types.GrantListEntry, error) {
	var all []types.GrantListEntry
	in := &kms.ListGrantsInput{KeyId: aws.String(arn)}
	for {
		page, err := c.ListGrants(ctx, in)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Grants...)
		if !page.Truncated {
			return all, nil
		}
		next := aws.ToString(page.NextMarker)
		if next == "" || next == aws.ToString(in.Marker) {
			return nil, errors.New("ListGrants answer is truncated but has no new NextMarker")
		}
		in.Marker = aws.String(next)
	}
}

func (k Keys) sealingContext() map[string]string {
	return map[string]string{ctxPurpose: purposeSealing, ctxSetup: k.setupHex()}
}

func (k Keys) keyContext(aad []byte) map[string]string {
	return map[string]string{keyContext: hex.EncodeToString(aad), ctxSetup: k.setupHex()}
}

// recordCredentials decrypts the S3 writer credentials inside
// the enclave. The blob under key in the host store (the images use
// record/writer-credentials.kms) is JSON {"access_key_id",
// "secret_access_key"} that the key admin encrypted with `aws kms encrypt
// --encryption-context purpose=record-creds` under the enclave's KMS key.
// The key policy lets only the measured enclave decrypt, so the parent
// never sees the credentials and cannot write the mark log itself.
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
// admin made under a locked policy, does not decrypt, and the start stops.
//
// The stored blob counts only when the store holds a sealed share
// (sharePrefix), that is when an earlier start of this runner sealed
// something under it. Otherwise dataKey ignores the blob and makes a new
// key (AWS-KMS-02). Before the key policy was locked, the key admin could
// encrypt a key it knows under the sealing context; that blob decrypts
// under the locked policy too, and its decryption does not show who chose
// the key. A new key costs nothing while no share is sealed. The ignored
// blob is kept under another name first (setAside), never destroyed.
//
// Any object under sharePrefix passes that check, and the host writes the
// store. So stored reports whether the key came from the stored blob: the
// runner then uses it only once every stored share opens under it, and
// seals no new share before (platform.Platform.SealingKeyStored).
func (k Keys) dataKey(ctx context.Context, store platform.Store) (key []byte, stored bool, err error) {
	rsaKey, recipient, err := k.Recipient()
	if err != nil {
		return nil, false, err
	}

	shares, err := store.List(sharePrefix)
	if err != nil {
		return nil, false, err
	}
	blob, err := store.Get(dataKeyBlob)
	if err == nil && len(shares) == 0 {
		if err := setAside(store, blob); err != nil {
			return nil, false, err
		}
		err = platform.ErrNotFound
	}
	switch {
	case errors.Is(err, platform.ErrNotFound):
		out, err := k.Client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
			KeyId: aws.String(k.KeyID), KeySpec: types.DataKeySpecAes256, EncryptionContext: k.sealingContext(), Recipient: recipient})
		if err != nil {
			return nil, false, fmt.Errorf("nitro: kms GenerateDataKey: %w", err)
		}
		if err := store.Put(dataKeyBlob, out.CiphertextBlob); err != nil {
			return nil, false, err
		}
		key, err := DecryptEnvelopedData(out.CiphertextForRecipient, rsaKey)
		return key, false, err
	case err != nil:
		return nil, false, err
	}
	out, err := k.Client.Decrypt(ctx, &kms.DecryptInput{
		KeyId: aws.String(k.KeyID), CiphertextBlob: blob, EncryptionContext: k.sealingContext(), Recipient: recipient})
	if notAuthentic(err) {
		return nil, false, fmt.Errorf("nitro: the stored sealing key %s does not decrypt under this KMS key and setup_hash %x: "+
			"it belongs to another setup or key, or the host put it there; a new setup starts on an empty store (%v)", dataKeyBlob, k.Setup, err)
	}
	if err != nil {
		return nil, false, fmt.Errorf("nitro: kms Decrypt: %w", err)
	}
	key, err = DecryptEnvelopedData(out.CiphertextForRecipient, rsaKey)
	return key, true, err
}

// setAside copies a sealing blob that dataKey ignores to
// sealing/datakey.kms.ignored-<first 8 bytes of its SHA-256, hex> before
// the new key overwrites it. If the shares were only missing from the
// listing (a partial restore, a late mount), the operator can put the
// copy back by hand (platform-aws/deploy/README.md). Every start without
// a share sets aside the blob the start before it made, so each such
// restart leaves one more copy; only a blob set aside a second time (the
// start failed after setAside) keeps its name.
func setAside(store platform.Store, blob []byte) error {
	sum := sha256.Sum256(blob)
	aside := fmt.Sprintf("%s.ignored-%x", dataKeyBlob, sum[:8])
	if err := store.Put(aside, blob); err != nil {
		return fmt.Errorf("nitro: keep the ignored sealing key blob as %s: %w", aside, err)
	}
	// The runner's own logger does not reach the platform: this goes to
	// the default logger, and the copy on the parent is the lasting trace.
	slog.Warn("nitro: no stored share, so the stored sealing key blob is not used; a new key replaces it (AWS-KMS-02)",
		"blob", dataKeyBlob, "copy", aside)
	return nil
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
//	kms_key_creation_date=1793895285         the key's CreationDate (optional)
//	proxy=kms.eu-west-1.amazonaws.com:443=vsock:3:8000[,host:port=addr...]
//	                                         also the NTS-KE hosts, port 4460
//	ntp_relay=vsock:3:7102                   the UDP relay on the parent, for
//	                                         the NTS clock's NTP (udprelay)
//	clock=system
//	record_creds=record/writer-credentials.kms   store key of the mark log's
//	                                             KMS-encrypted S3 credentials
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
	keys := &Keys{Client: client, KeyID: keyID, Setup: o.SetupHash,
		Recipient: func() (*rsa.PrivateKey, *types.RecipientInfo, error) { return kmsRecipient(n, seen) }}
	if s := o.Param("kms_key_creation_date", ""); s != "" {
		if keys.CreationDate, err = strconv.ParseInt(s, 10, 64); err != nil || keys.CreationDate <= 0 {
			return fail(fmt.Errorf("nitro: kms_key_creation_date %q is not Unix seconds", s))
		}
	}

	// key_release_hash and the lock, read before the sealing key is made or
	// opened. On mainnet a key policy someone can still change stops the
	// start here. Every later call names the key by the ARN read here.
	rule, keyARN, err := readKeyRule(context.Background(), o, *keys)
	if err != nil {
		return fail(err)
	}
	keys.KeyID = keyARN
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key, stored, err := keys.dataKey(ctx, agent)
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
		// AWS-KMS-02: a stored blob may be one the key admin made before
		// the key policy was locked.
		SealingKeyStored: stored,
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

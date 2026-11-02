// Package markstore keeps a signer's slashing mark in an append-only log
// that nobody can rewrite: an S3 bucket with Object Lock in compliance mode,
// a Cloud Storage bucket with a locked retention policy, or an Azure Blob
// container with a locked time-based retention policy. Each record is one
// object, named by its version, created only if that name never existed,
// and signed by a key only the attested runner holds.
//
// Why: a cloud runner's local state lives on storage the host can roll
// back, so without an external mark it restarts from the clock floor, and
// the floor's source bound stalls signing while the chain does not finalize. With the log
// the runner restarts from its true mark: the source bound comes from the
// log, and the floor keeps only target and block bounds.
//
// What the log guarantees (section 2 of the note): the host can delay or
// drop requests (the runner then fails closed), and the account admin can
// neither delete nor overwrite a locked record. What is left to an admin is
// adding objects, hiding the newest record in a listing (S3 delete marker,
// a soft-deleted generation) and replaying old record bytes under new names.
// The reader covers those: it lists every version, verifies each record's
// signature, signer and name, takes the highest valid version, and checks
// the chain link to the record before it.
package markstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lidofinance/tee-signer/platform"
)

var (
	// ErrExists: an object of that name exists (or existed), so a create
	// did not write. On a locked log nothing ever replaces it.
	ErrExists = errors.New("markstore: object exists")
	// ErrNotFound: no object of that name.
	ErrNotFound = errors.New("markstore: not found")
	// ErrHidden: a create landed, but the name holds another object or a
	// delete marker as well, so something hid an object of that name
	// (S3: a delete marker over a clone's record). The mark log reads it
	// as another instance's write.
	ErrHidden = errors.New("markstore: a delete marker or another version hides an object of this name")
)

// Entry is one object of a listing: its name and the store's reference to
// that exact object (S3 version ID, GCS generation; empty where names are
// never reused).
type Entry struct {
	Name string
	Ref  string
}

// Log is the store side: the subset of an object store API the mark log
// needs, with write-once semantics.
type Log interface {
	// Create writes data under name only if no object of that name exists
	// (S3 If-None-Match: *, GCS ifGenerationMatch=0, Azure If-None-Match: *).
	// ErrExists otherwise. A nil error means the object is durable.
	Create(ctx context.Context, name string, data []byte) error
	// List returns every object under prefix, every version of it where
	// the store keeps versions, so a delete marker or a newer object of the
	// same name cannot hide one.
	List(ctx context.Context, prefix string) ([]Entry, error)
	// Get reads the object of an entry.
	Get(ctx context.Context, e Entry) ([]byte, error)
	String() string
}

// Env is what Open needs from the platform: an HTTP client and the
// credentials of the platform's store. Each must be something only the
// attested runner holds.
type Env struct {
	HTTP *http.Client
	// AWSCreds signs S3 requests (SigV4).
	AWSCreds func(ctx context.Context) (platform.Credentials, error)
	// Token returns an OAuth bearer token for the store (GCS: the federated
	// token of the Confidential Space flow; Azure: the managed identity's
	// token for https://storage.azure.com/).
	Token func(ctx context.Context) (string, error)
	// TokenRefused, if set, tells Token's cache that the store answered 401
	// to a token (TokenCache.Invalidate). The Azure store then takes a
	// fresh token and sends the request once more.
	TokenRefused func(token string)
	// ARMToken returns the managed identity's token for
	// https://management.azure.com/. Azure only: the container's
	// immutability policy is visible in the management plane only (Lock).
	ARMToken func(ctx context.Context) (string, error)
	// ARMTokenRefused is TokenRefused for ARMToken.
	ARMTokenRefused func(token string)
	// RetainDays, if not 0, is the retention in days each object the store
	// creates must get by itself (slashing_log_min_lock_days). S3: every
	// PUT names compliance mode and a date at least this far ahead, because
	// the bucket's default retention is a setting its admin can lower or
	// remove after the lock check. GCS and Azure lock the policy itself and
	// ignore it.
	RetainDays uint32
}

// opener opens one store kind. The platform builds register theirs
// (s3 in the AWS build, gcs in the GCP build, azblob in the Azure build).
type opener func(rest string, env Env) (Log, error)

var openers = map[string]opener{}

// Register adds a store kind to Open. Called from init in the platform
// build's own file.
func Register(kind string, o func(rest string, env Env) (Log, error)) { openers[kind] = o }

// Open parses a -mark-store value:
//
//	none
//	file:DIR                                         tests and the dev platform
//	s3:bucket=B,region=R[,endpoint=URL]              AWS build
//	gcs:bucket=B[,endpoint=URL]                      GCP build
//	azblob:account=A,container=C[,endpoint=URL]      Azure build
//	       [,subscription=S,resource_group=G[,arm_endpoint=URL]]  for the lock check
//
// It returns nil for "none" and "".
func Open(spec string, env Env) (Log, error) {
	kind, rest, _ := strings.Cut(spec, ":")
	switch kind {
	case "", "none":
		return nil, nil
	case "file":
		if rest == "" {
			return nil, errors.New("markstore: file: needs a directory")
		}
		return NewFileLog(rest)
	}
	if o, ok := openers[kind]; ok {
		return o(rest, env)
	}
	return nil, fmt.Errorf("markstore: store %q is not built into this binary (each platform build has its own)", kind)
}

// Params parses "k=v,k=v" and checks that the required keys are there and
// no others.
func Params(rest string, required, optional []string) (map[string]string, error) {
	out := map[string]string{}
	known := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		known[k] = true
	}
	for _, kv := range strings.Split(rest, ",") {
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !known[k] || v == "" {
			return nil, fmt.Errorf("markstore: bad parameter %q (want %s)", kv, strings.Join(append(required, optional...), ", "))
		}
		out[k] = v
	}
	for _, k := range required {
		if out[k] == "" {
			return nil, fmt.Errorf("markstore: missing %s=", k)
		}
	}
	return out, nil
}

// FileLog is a write-once log in a local directory, for tests and the dev
// platform. Files are created with O_EXCL and made read-only. The host owns
// the directory, so it can delete or roll back files: it gives the format,
// the reader and the conflict rules a test bed, not the locked storage's
// guarantee.
type FileLog struct{ dir string }

// NewFileLog creates dir if needed.
func NewFileLog(dir string) (*FileLog, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileLog{dir: dir}, nil
}

func (f *FileLog) path(name string) (string, error) {
	if name == "" || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("markstore: bad name %q", name)
	}
	return filepath.Join(f.dir, filepath.FromSlash(name)), nil
}

func (f *FileLog) Create(_ context.Context, name string, data []byte) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	// Write to a temp file, then link it to the name: link fails if the
	// name exists, so a create never replaces an object and a crash leaves
	// either nothing or the whole record.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return err
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (f *FileLog) List(_ context.Context, prefix string) ([]Entry, error) {
	p, err := f.path(prefix)
	if err != nil {
		return nil, err
	}
	dir, base := filepath.Dir(p), filepath.Base(p)
	if strings.HasSuffix(prefix, "/") {
		dir, base = p, ""
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rel, _ := filepath.Rel(f.dir, dir)
	var out []Entry
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".tmp-") || !strings.HasPrefix(e.Name(), base) {
			continue
		}
		out = append(out, Entry{Name: filepath.ToSlash(filepath.Join(rel, e.Name()))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *FileLog) Get(_ context.Context, e Entry) ([]byte, error) {
	p, err := f.path(e.Name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (f *FileLog) String() string { return "file:" + f.dir }

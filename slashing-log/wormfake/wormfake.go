// Package wormfake has in-process HTTP fakes of the three object stores the
// mark log uses, with write-once semantics, for tests only (nothing in a
// runner binary imports it). Each fake implements only the requests the
// clients make:
//
//	S3     PUT object (If-None-Match: *), GET object (versionId),
//	       GET bucket?versions (ListObjectVersions), with versioning and
//	       Object Lock in compliance mode
//	GCS    POST upload (ifGenerationMatch=0), GET object (alt=media,
//	       generation), GET list (versions=true), with a locked retention
//	       policy
//	Azure  PUT blob (If-None-Match: *), GET blob, GET list (comp=list),
//	       with a locked time-based retention policy
//
// and the lock self-check's read of the lock (S3 GET ?object-lock, GCS GET
// bucket with its retentionPolicy, Azure the management plane's
// immutability policy); and the faults the tests need: the store down, slow
// answers, a stale listing, a listing that leaves names out, a lock in the
// wrong mode or with too short a retention, records that expired (a fake
// clock and the admin deleting what the retention no longer keeps), and the
// admin's attempts to roll a record back (overwrite, delete, delete marker,
// a new version of the name, a copy of an old record under a new name).
// What the real locked store refuses, the fakes refuse; what it allows (S3
// new versions and delete markers, new names anywhere, deleting an object
// whose retention ended), they allow.
package wormfake

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind of fake.
type Kind int

const (
	S3 Kind = iota
	GCS
	Azure
)

func (k Kind) String() string { return [...]string{"s3", "gcs", "azure"}[k] }

type version struct {
	id     string
	data   []byte
	marker bool      // S3 delete marker
	seq    int       // global write order, for stale listings
	at     time.Time // written, on the fake clock
}

// Lock is the fake's retention lock, the one its lock read reports and its
// expiry follows.
type Lock struct {
	None       bool // no lock at all (S3: no Object Lock configuration; GCS: no policy; Azure: no policy)
	Compliance bool // S3 COMPLIANCE (else GOVERNANCE); GCS and Azure locked (else unlocked)
	Days       int  // retention of each object
}

// Server is one fake store with one bucket or container.
type Server struct {
	Kind   Kind
	Bucket string
	*httptest.Server

	// Auth checks a request's credentials; nil accepts any request that
	// carries an Authorization header.
	Auth func(r *http.Request) error
	// PageSize bounds each listing page (default 3, so tests page).
	PageSize int

	mu       sync.Mutex
	objects  map[string][]*version // name -> versions, oldest first
	seq      int
	down     bool
	delay    time.Duration
	staleBy  int    // listings omit the last staleBy writes
	hidden   string // listings omit names with this prefix ("": none)
	lock     Lock
	offset   time.Duration // the fake clock runs this far ahead of the real one
	faults   []*Fault
	hits     int
	Requests map[string]int
	Refused  []string // admin attempts the lock refused
}

// DefaultLock is the lock a new fake has: compliance, 30 days.
var DefaultLock = Lock{Compliance: true, Days: 30}

// New starts a fake of kind k.
func New(k Kind, bucket string) *Server {
	s := &Server{Kind: k, Bucket: bucket, objects: map[string][]*version{}, Requests: map[string]int{}, PageSize: 3,
		lock: DefaultLock}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Now is the fake clock: the store's time, which the tests also give the
// mark log as its trusted clock.
func (s *Server) Now() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return time.Now().Add(s.offset) }

// Advance moves the fake clock forward.
func (s *Server) Advance(d time.Duration) { s.mu.Lock(); s.offset += d; s.mu.Unlock() }

// SetLock sets the lock the store reports and its retention.
func (s *Server) SetLock(l Lock) { s.mu.Lock(); s.lock = l; s.mu.Unlock() }

// SetHidden makes listings leave out every name that starts with prefix
// (a listing that hides objects); "" shows everything again.
func (s *Server) SetHidden(prefix string) { s.mu.Lock(); s.hidden = prefix; s.mu.Unlock() }

// AdminDeleteExpired deletes every object version whose retention has
// ended on the fake clock, as an admin may: records expire oldest first.
// It returns how many versions it deleted.
func (s *Server) AdminDeleteExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := time.Duration(s.lock.Days) * 24 * time.Hour
	if s.lock.None {
		keep = 0
	}
	now := time.Now().Add(s.offset)
	n := 0
	for name, vs := range s.objects {
		var left []*version
		for _, v := range vs {
			if now.Sub(v.at) >= keep {
				n++
				continue
			}
			left = append(left, v)
		}
		if len(left) == 0 {
			delete(s.objects, name)
		} else {
			s.objects[name] = left
		}
	}
	return n
}

// SetDown makes every request fail with 503 (or recovers).
func (s *Server) SetDown(down bool) { s.mu.Lock(); s.down = down; s.mu.Unlock() }

// SetDelay delays every answer.
func (s *Server) SetDelay(d time.Duration) { s.mu.Lock(); s.delay = d; s.mu.Unlock() }

// SetStale makes listings leave out the last n writes (a lagging replica).
func (s *Server) SetStale(n int) { s.mu.Lock(); s.staleBy = n; s.mu.Unlock() }

// Action is what a Fault does to a request it matches.
type Action int

const (
	// FailBeforeApply answers 503 and writes nothing.
	FailBeforeApply Action = iota + 1
	// ApplyThenDropReply runs the request, then closes the connection
	// before any reply: a write that landed but whose reply the host
	// dropped.
	ApplyThenDropReply
)

// Fault is one entry of the fault plan (AddFault).
type Fault struct {
	Method string // HTTP method; "" matches any
	// Match is a substring of the request's path and unescaped query,
	// usually an object name or its prefix; "" matches any.
	Match  string
	Action Action
	// Times is how many matching requests it hits; 0 means once.
	Times int
}

// AddFault adds f to the fault plan. Faults hit in the order added; each
// stops matching once it has hit Times requests.
func (s *Server) AddFault(f Fault) {
	if f.Times <= 0 {
		f.Times = 1
	}
	s.mu.Lock()
	s.faults = append(s.faults, &f)
	s.mu.Unlock()
}

// Hits is how many requests the fault plan has hit so far.
func (s *Server) Hits() int { s.mu.Lock(); defer s.mu.Unlock(); return s.hits }

// faultFor returns the action of the first fault r matches and uses one of
// its hits; 0 when none matches. Call with s.mu held.
func (s *Server) faultFor(r *http.Request) Action {
	q, _ := url.QueryUnescape(r.URL.RawQuery)
	target := r.URL.Path + "?" + q
	for _, f := range s.faults {
		if f.Times == 0 || f.Method != "" && f.Method != r.Method || !strings.Contains(target, f.Match) {
			continue
		}
		f.Times--
		s.hits++
		return f.Action
	}
	return 0
}

// dropReply runs the handler on a recorder, so the request takes effect,
// and then closes the connection without writing the recorded answer.
func dropReply(w http.ResponseWriter, run func(http.ResponseWriter)) {
	run(httptest.NewRecorder())
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, err := hj.Hijack(); err == nil {
			c.Close()
			return
		}
	}
	// No hijack (HTTP/2): an error status still tells the client nothing landed.
	http.Error(w, "reply lost", http.StatusBadGateway)
}

// Names returns the object names, sorted.
func (s *Server) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for n := range s.objects {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Current returns the bytes of the newest non-marker version of name.
func (s *Server) Current(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	vs := s.objects[name]
	for i := len(vs) - 1; i >= 0; i-- {
		if !vs[i].marker {
			return vs[i].data, true
		}
	}
	return nil, false
}

// ---- admin actions (the account admin, outside the runner) ----

// AdminOverwrite writes data under an existing name without a condition.
// S3 with versioning: a new current version (allowed, the locked one
// stays). GCS and Azure with a locked policy: refused.
func (s *Server) AdminOverwrite(name string, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[name]; ok && s.Kind != S3 {
		s.Refused = append(s.Refused, "overwrite "+name)
		return false
	}
	s.put(name, data, false)
	return true
}

// AdminDelete deletes a locked object version: always refused.
func (s *Server) AdminDelete(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Refused = append(s.Refused, "delete "+name)
	return false
}

// AdminDeleteMarker hides an S3 object behind a delete marker (allowed on
// a locked bucket); GCS and Azure have none: refused.
func (s *Server) AdminDeleteMarker(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Kind != S3 {
		s.Refused = append(s.Refused, "delete marker "+name)
		return false
	}
	s.put(name, nil, true)
	return true
}

// AdminNoncurrent makes the live GCS generation of name noncurrent, as a
// delete on a bucket with object versioning on does: the generation stays
// readable and listed (versions=true), and the name looks free to a create
// with ifGenerationMatch=0. The fake allows it under the lock too, because
// whether Cloud Storage does with Bucket Lock is not verified (RBRLOG-01).
// S3 and Azure: refused.
func (s *Server) AdminNoncurrent(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Kind != GCS || s.current(name) == nil {
		s.Refused = append(s.Refused, "noncurrent "+name)
		return false
	}
	s.put(name, nil, true)
	return true
}

// AdminCreate writes a new name (allowed everywhere: retention locks what
// exists, it does not stop new objects).
func (s *Server) AdminCreate(name string, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[name]; ok && s.Kind != S3 {
		s.Refused = append(s.Refused, "create over "+name)
		return false
	}
	s.put(name, data, false)
	return true
}

func (s *Server) put(name string, data []byte, marker bool) *version {
	s.seq++
	v := &version{id: strconv.Itoa(1000 + s.seq), data: append([]byte(nil), data...), marker: marker, seq: s.seq,
		at: time.Now().Add(s.offset)}
	s.objects[name] = append(s.objects[name], v)
	return v
}

// current returns the current version of name, nil if none or a marker.
func (s *Server) current(name string) *version {
	vs := s.objects[name]
	if len(vs) == 0 || vs[len(vs)-1].marker {
		return nil
	}
	return vs[len(vs)-1]
}

// ---- HTTP ----

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	down, delay := s.down, s.delay
	s.Requests[r.Method]++
	s.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if down {
		http.Error(w, "store down", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "no credentials", http.StatusForbidden)
		return
	}
	if s.Auth != nil {
		if err := s.Auth(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.mu.Lock()
	defer s.mu.Unlock()
	run := func(w http.ResponseWriter) {
		switch s.Kind {
		case S3:
			s.serveS3(w, r, body)
		case GCS:
			s.serveGCS(w, r, body)
		case Azure:
			s.serveAzure(w, r, body)
		}
	}
	switch s.faultFor(r) {
	case FailBeforeApply:
		http.Error(w, "injected fault", http.StatusServiceUnavailable)
	case ApplyThenDropReply:
		dropReply(w, run)
	default:
		run(w)
	}
}

// listing returns name -> versions visible to a listing (stale ones cut).
func (s *Server) listing(prefix string) []struct {
	name string
	v    *version
} {
	limit := s.seq - s.staleBy
	var out []struct {
		name string
		v    *version
	}
	for n, vs := range s.objects {
		if !strings.HasPrefix(n, prefix) || s.hidden != "" && strings.HasPrefix(n, s.hidden) {
			continue
		}
		for _, v := range vs {
			if v.seq <= limit {
				out = append(out, struct {
					name string
					v    *version
				}{n, v})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].v.seq < out[j].v.seq
	})
	return out
}

func s3err(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func (s *Server) serveS3(w http.ResponseWriter, r *http.Request, body []byte) {
	path := strings.TrimPrefix(r.URL.Path, "/"+s.Bucket)
	key := strings.TrimPrefix(path, "/")
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodPut && key != "":
		// Object Lock buckets need Content-MD5 (or an x-amz-checksum-*
		// header, which the client does not send). S3 checks both digests
		// against the body.
		sum := md5.Sum(body)
		switch md := r.Header.Get("Content-MD5"); {
		case md == "":
			s3err(w, http.StatusBadRequest, "InvalidRequest")
			return
		case md != base64.StdEncoding.EncodeToString(sum[:]):
			s3err(w, http.StatusBadRequest, "BadDigest")
			return
		}
		if h := r.Header.Get("x-amz-content-sha256"); h != "UNSIGNED-PAYLOAD" {
			bh := sha256.Sum256(body)
			if h != hex.EncodeToString(bh[:]) {
				s3err(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
				return
			}
		}
		if r.Header.Get("If-None-Match") == "*" && s.current(key) != nil {
			s3err(w, http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		v := s.put(key, body, false)
		w.Header().Set("x-amz-version-id", v.id)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && key != "":
		vid := q.Get("versionId")
		for _, v := range s.objects[key] {
			if (vid == "" && v == s.current(key)) || (vid != "" && v.id == vid) {
				if v.marker {
					break
				}
				_, _ = w.Write(v.data)
				return
			}
		}
		s3err(w, http.StatusNotFound, "NoSuchKey")
	case r.Method == http.MethodGet && key == "" && q.Has("versions"):
		all := s.listing(q.Get("prefix"))
		start := 0
		if km := q.Get("key-marker"); km != "" {
			for i, e := range all {
				if e.name == km && e.v.id == q.Get("version-id-marker") {
					start = i + 1
				}
			}
		}
		type ver struct {
			Key       string `xml:"Key"`
			VersionID string `xml:"VersionId"`
		}
		var res struct {
			XMLName             xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult"`
			IsTruncated         bool     `xml:"IsTruncated"`
			NextKeyMarker       string   `xml:"NextKeyMarker,omitempty"`
			NextVersionIDMarker string   `xml:"NextVersionIdMarker,omitempty"`
			Versions            []ver    `xml:"Version"`
			DeleteMarkers       []ver    `xml:"DeleteMarker"`
		}
		end := min(len(all), start+s.PageSize)
		for _, e := range all[start:end] {
			if e.v.marker {
				res.DeleteMarkers = append(res.DeleteMarkers, ver{e.name, e.v.id})
			} else {
				res.Versions = append(res.Versions, ver{e.name, e.v.id})
			}
		}
		if end < len(all) {
			res.IsTruncated = true
			res.NextKeyMarker, res.NextVersionIDMarker = all[end-1].name, all[end-1].v.id
		}
		_ = xml.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet && key == "" && q.Has("object-lock"):
		if s.lock.None {
			s3err(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError")
			return
		}
		mode := "GOVERNANCE"
		if s.lock.Compliance {
			mode = "COMPLIANCE"
		}
		fmt.Fprintf(w, `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled>`+
			`<Rule><DefaultRetention><Mode>%s</Mode><Days>%d</Days></DefaultRetention></Rule></ObjectLockConfiguration>`, mode, s.lock.Days)
	default:
		s3err(w, http.StatusNotImplemented, "NotImplemented")
	}
}

func gcsErr(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "message": msg}})
}

func (s *Server) serveGCS(w http.ResponseWriter, r *http.Request, body []byte) {
	q := r.URL.Query()
	upload := "/upload/storage/v1/b/" + s.Bucket + "/o"
	objs := "/storage/v1/b/" + s.Bucket + "/o"
	switch {
	case r.Method == http.MethodPost && r.URL.Path == upload:
		name := q.Get("name")
		if q.Get("uploadType") != "media" || name == "" {
			gcsErr(w, http.StatusBadRequest, "bad upload")
			return
		}
		if q.Get("ifGenerationMatch") == "0" && s.current(name) != nil {
			gcsErr(w, http.StatusPreconditionFailed, "At least one of the pre-conditions you specified did not hold.")
			return
		}
		if s.current(name) != nil {
			gcsErr(w, http.StatusForbidden, "object is under retention and cannot be replaced")
			return
		}
		v := s.put(name, body, false)
		_ = json.NewEncoder(w).Encode(map[string]string{"name": name, "generation": v.id})
	case r.Method == http.MethodGet && r.URL.Path == objs:
		all := s.listing(q.Get("prefix"))
		start, _ := strconv.Atoi(q.Get("pageToken"))
		end := min(len(all), start+s.PageSize)
		type item struct {
			Name       string `json:"name"`
			Generation string `json:"generation"`
		}
		res := struct {
			Items         []item `json:"items,omitempty"`
			NextPageToken string `json:"nextPageToken,omitempty"`
		}{}
		for _, e := range all[start:end] {
			if e.v.marker {
				continue // a noncurrent mark is no generation (AdminNoncurrent)
			}
			res.Items = append(res.Items, item{e.name, e.v.id})
		}
		if end < len(all) {
			res.NextPageToken = strconv.Itoa(end)
		}
		_ = json.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, objs+"/"):
		name, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), objs+"/"))
		if err != nil || q.Get("alt") != "media" {
			gcsErr(w, http.StatusBadRequest, "bad get")
			return
		}
		for _, v := range s.objects[name] {
			if v.marker {
				continue
			}
			if q.Get("generation") == "" && v == s.current(name) || v.id == q.Get("generation") {
				_, _ = w.Write(v.data)
				return
			}
		}
		gcsErr(w, http.StatusNotFound, "No such object")
	case r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/"+s.Bucket:
		if s.lock.None {
			_, _ = io.WriteString(w, "{}")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"retentionPolicy": map[string]any{
			"retentionPeriod": strconv.Itoa(s.lock.Days * 86400), "effectiveTime": "2026-10-01T00:00:00Z", "isLocked": s.lock.Compliance}})
	default:
		gcsErr(w, http.StatusNotImplemented, "not implemented")
	}
}

func azErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("x-ms-error-code", code)
	w.WriteHeader(status)
	fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

// ARMPath is the management-plane path of the fake container's
// immutability policy, for the given subscription, resource group and
// account.
func (s *Server) ARMPath(sub, rg, account string) string {
	return "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.Storage/storageAccounts/" + account +
		"/blobServices/default/containers/" + s.Bucket + "/immutabilityPolicies/default"
}

// serveARM answers the management plane's Get Immutability Policy for any
// subscription, resource group and account, and this container.
func (s *Server) serveARM(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if r.Method != http.MethodGet || len(parts) != 15 || r.URL.Path != s.ARMPath(parts[2], parts[4], parts[8]) || r.URL.Query().Get("api-version") == "" {
		http.Error(w, `{"error":{"code":"InvalidResourceType"}}`, http.StatusBadRequest)
		return
	}
	if s.lock.None {
		http.Error(w, `{"error":{"code":"ImmutabilityPolicyNotFound"}}`, http.StatusNotFound)
		return
	}
	state := "Unlocked"
	if s.lock.Compliance {
		state = "Locked"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"name": "default", "etag": `"8d0"`,
		"type":       "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies",
		"properties": map[string]any{"immutabilityPeriodSinceCreationInDays": s.lock.Days, "state": state, "allowProtectedAppendWrites": false}})
}

func (s *Server) serveAzure(w http.ResponseWriter, r *http.Request, body []byte) {
	if strings.HasPrefix(r.URL.Path, "/subscriptions/") {
		s.serveARM(w, r)
		return
	}
	if r.Header.Get("x-ms-version") == "" {
		azErr(w, http.StatusBadRequest, "MissingRequiredHeader")
		return
	}
	q := r.URL.Query()
	base := "/" + s.Bucket
	switch {
	case r.Method == http.MethodGet && r.URL.Path == base && q.Get("comp") == "list":
		all := s.listing(q.Get("prefix"))
		start, _ := strconv.Atoi(q.Get("marker"))
		end := min(len(all), start+s.PageSize)
		type blob struct {
			Name string `xml:"Name"`
		}
		var res struct {
			XMLName    xml.Name `xml:"EnumerationResults"`
			Blobs      []blob   `xml:"Blobs>Blob"`
			NextMarker string   `xml:"NextMarker"`
		}
		for _, e := range all[start:end] {
			res.Blobs = append(res.Blobs, blob{e.name})
		}
		if end < len(all) {
			res.NextMarker = strconv.Itoa(end)
		}
		_ = xml.NewEncoder(w).Encode(res)
	case strings.HasPrefix(r.URL.Path, base+"/"):
		name := strings.TrimPrefix(r.URL.Path, base+"/")
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("x-ms-blob-type") != "BlockBlob" {
				azErr(w, http.StatusBadRequest, "InvalidHeaderValue")
				return
			}
			if s.current(name) != nil {
				if r.Header.Get("If-None-Match") == "*" {
					azErr(w, http.StatusConflict, "BlobAlreadyExists")
				} else {
					azErr(w, http.StatusConflict, "BlobImmutableDueToPolicy")
				}
				return
			}
			s.put(name, body, false)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			if v := s.current(name); v != nil {
				_, _ = w.Write(v.data)
				return
			}
			azErr(w, http.StatusNotFound, "BlobNotFound")
		default:
			azErr(w, http.StatusConflict, "BlobImmutableDueToPolicy")
		}
	default:
		azErr(w, http.StatusBadRequest, "UnsupportedRequest")
	}
}

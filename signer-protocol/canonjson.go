package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// CanonicalJSON is b in one fixed form, for key_release_hash of an AWS key
// policy: AWS KMS GetKeyPolicy returns the same policy with the members of
// an object (the keys of a Condition map, for one) in another order on
// each call, so the text as KMS returns it is no stable hash input. The
// form: object members sorted by name (byte order of the UTF-8), arrays in
// their order, no whitespace, strings escaped as encoding/json does
// without HTML escaping, and numbers as written in b. b must be one JSON
// value; trailing data, a member that appears twice in one object, or
// nesting deeper than 64 is an error.
func CanonicalJSON(b []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := canonicalValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("canonical JSON: data after the value")
	}
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// canonicalValue reads one value from d. Objects become maps, which
// encoding/json writes with sorted keys; numbers stay json.Number.
func canonicalValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("canonical JSON: nested too deep")
	}
	t, err := d.Token()
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return nil, fmt.Errorf("canonical JSON: %w", err)
			}
			k := kt.(string)
			if _, dup := m[k]; dup {
				return nil, fmt.Errorf("canonical JSON: member %q appears twice", k)
			}
			if m[k], err = canonicalValue(d, depth+1); err != nil {
				return nil, err
			}
		}
		_, err = d.Token() // '}'
		return m, err
	case json.Delim('['):
		s := []any{}
		for d.More() {
			v, err := canonicalValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		_, err = d.Token() // ']'
		return s, err
	}
	return t, nil
}

package platform

import "fmt"

// Change is a set of store writes that belong together: a key generation
// commit (the shares and their key records), the key records a lock
// closes. Apply writes it.
type Change struct{ ops []ChangeOp }

// ChangeOp is one write of a Change: a put, or a delete when Delete is set.
type ChangeOp struct {
	Key    string
	Value  []byte
	Delete bool
}

// Put adds a put of val under key.
func (c *Change) Put(key string, val []byte) { c.ops = append(c.ops, ChangeOp{Key: key, Value: val}) }

// Delete adds a delete of key.
func (c *Change) Delete(key string) { c.ops = append(c.ops, ChangeOp{Key: key, Delete: true}) }

// Ops returns the writes in the order they were added.
func (c *Change) Ops() []ChangeOp { return c.ops }

// Deleter is a Store that can remove a key. Removing a missing key is no
// error.
type Deleter interface {
	Delete(key string) error
}

// Batcher is a Store that writes a whole Change at once: after a failed
// call or a crash, it and a restart hold all of the change or none of it
// (runner/statestore).
type Batcher interface {
	Apply(c *Change) error
}

// Apply writes c to s. A Batcher takes it at once. Any other store gets
// the writes one by one, in order, so an error or a crash can leave the
// first ones written: callers order a change so that each of its prefixes
// is a state the runner can start from. A delete needs a Deleter.
func Apply(s Store, c *Change) error {
	if b, ok := s.(Batcher); ok {
		return b.Apply(c)
	}
	for _, op := range c.ops {
		if !op.Delete {
			if err := s.Put(op.Key, op.Value); err != nil {
				return err
			}
			continue
		}
		d, ok := s.(Deleter)
		if !ok {
			return fmt.Errorf("platform: this store cannot delete %s", op.Key)
		}
		if err := d.Delete(op.Key); err != nil {
			return err
		}
	}
	return nil
}

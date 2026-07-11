package shared

import (
	"sync"

	"github.com/projectdiscovery/hmap/store/hybrid"
)

// Dedup wraps a hybrid hashmap for deduplication.
type Dedup struct {
	hm *hybrid.HybridMap
	mu sync.Mutex
}

// NewDedup creates a new deduplication instance.
func NewDedup() (*Dedup, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}
	return &Dedup{hm: hm}, nil
}

// Seen reports whether the key has been seen before.
func (d *Dedup) Seen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.hm.Get(key)
	return ok
}

// Set marks a key as seen.
func (d *Dedup) Set(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_ = d.hm.Set(key, nil)
}

// TestAndSet returns true if the key is new (not seen before), and marks it.
func (d *Dedup) TestAndSet(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.hm.Get(key); ok {
		return false
	}
	_ = d.hm.Set(key, nil)
	return true
}

// Scan iterates over all keys.
func (d *Dedup) Scan(fn func(k []byte) error) {
	// Ignore Scan return value; used for iteration only
	d.hm.Scan(func(k, _ []byte) error {
		_ = fn(k)
		return nil
	})
}

// Reset clears the map.
func (d *Dedup) Reset() {
	_ = d.hm.Close()
	hm, _ := hybrid.New(hybrid.DefaultDiskOptions)
	d.hm = hm
}

// Close closes the underlying store.
func (d *Dedup) Close() {
	_ = d.hm.Close()
}

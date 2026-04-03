package pki

import (
	"sort"
	"sync"
)

// Blocklist tracks blocked certificate fingerprints.
type Blocklist struct {
	mu           sync.RWMutex
	fingerprints map[string]struct{}
}

// NewBlocklist creates an empty blocklist.
func NewBlocklist() *Blocklist {
	return &Blocklist{
		fingerprints: make(map[string]struct{}),
	}
}

// Add adds a fingerprint to the blocklist.
func (b *Blocklist) Add(fingerprint string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fingerprints[fingerprint] = struct{}{}
}

// Remove removes a fingerprint from the blocklist.
func (b *Blocklist) Remove(fingerprint string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fingerprints, fingerprint)
}

// Contains checks if a fingerprint is in the blocklist.
func (b *Blocklist) Contains(fingerprint string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.fingerprints[fingerprint]
	return ok
}

// List returns all fingerprints in the blocklist, sorted.
func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]string, 0, len(b.fingerprints))
	for fp := range b.fingerprints {
		result = append(result, fp)
	}
	sort.Strings(result)
	return result
}

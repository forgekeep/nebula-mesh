package pop

import (
	"container/list"
	"sync"
	"time"
)

// NonceCacheConfig configures NonceCache. Zero-valued IdleTTL falls back to
// 10 minutes; zero Capacity falls back to 65536 (ADR 0004 §7.1 specifics).
type NonceCacheConfig struct {
	Capacity int
	IdleTTL  time.Duration
	// Now is injectable for tests. Defaults to time.Now when nil.
	Now func() time.Time
}

// NonceCache tracks recently observed (host_id, nonce) pairs to defeat
// poll-request replays inside the timestamp window (ADR 0004 §7.1).
//
// Implementation: a doubly linked list + map guarded by a single mutex.
// Each entry is evicted either when the LRU exceeds Capacity or when its
// idle age exceeds IdleTTL. Both bounds are required because real traffic
// is dominated by many short-lived hosts.
type NonceCache struct {
	mu      sync.Mutex
	cap     int
	idleTTL time.Duration
	now     func() time.Time
	order   *list.List // front = newest, back = oldest
	items   map[string]*list.Element
}

type nonceEntry struct {
	key      string
	lastSeen time.Time
}

// NewNonceCache constructs a NonceCache with sensible defaults.
func NewNonceCache(cfg NonceCacheConfig) *NonceCache {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 65536
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 10 * time.Minute
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &NonceCache{
		cap:     cfg.Capacity,
		idleTTL: cfg.IdleTTL,
		now:     now,
		order:   list.New(),
		items:   make(map[string]*list.Element),
	}
}

// SeenOrAdd records the (hostID, nonce) pair if it has not been observed
// within the active window. Returns true when the pair is freshly inserted
// (caller may proceed) and false when it duplicates an existing live entry
// (caller must reject with reason=replayed_nonce).
func (c *NonceCache) SeenOrAdd(hostID, nonce string) bool {
	key := hostID + "\x00" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if el, ok := c.items[key]; ok {
		entry := el.Value.(*nonceEntry)
		if now.Sub(entry.lastSeen) >= c.idleTTL {
			c.removeEl(el)
		} else {
			// Live duplicate: replay. Bump recency to defeat
			// flood-then-replay tactics.
			entry.lastSeen = now
			c.order.MoveToFront(el)
			return false
		}
	}

	entry := &nonceEntry{key: key, lastSeen: now}
	el := c.order.PushFront(entry)
	c.items[key] = el
	for c.order.Len() > c.cap {
		c.removeEl(c.order.Back())
	}
	return true
}

func (c *NonceCache) removeEl(el *list.Element) {
	entry := el.Value.(*nonceEntry)
	delete(c.items, entry.key)
	c.order.Remove(el)
}

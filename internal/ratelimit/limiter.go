// Package ratelimit implements an in-memory per-IP, per-route-group
// token-bucket limiter that the API and Web UI mount as middleware.
//
// Per the issue scope, the limiter is single-node by design — operators
// running multiple replicas should rate-limit at the load balancer
// instead. The map is bounded by an LRU per shard so a flood cannot
// blow up the server's memory.
package ratelimit

import (
	"container/list"
	"hash/fnv"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// GroupConfig is the per-route-group rate/burst pair.
type GroupConfig struct {
	Rate  float64 // requests per second
	Burst int     // bucket capacity
}

// Config drives the limiter.
type Config struct {
	Enabled          bool
	TrustProxyHeader bool
	Groups           map[string]GroupConfig
	// MaxEntriesPerShard caps the per-shard LRU. Default 65536.
	MaxEntriesPerShard int
	// Shards is the number of shards. Power-of-two recommended. Default 4.
	Shards int
}

// Default returns a Config that matches the defaults documented in
// issue #52: tight on auth + enrolment, loose on everything else.
func Default() Config {
	return Config{
		Enabled:          true,
		TrustProxyHeader: false,
		Groups: map[string]GroupConfig{
			"auth":         {Rate: 5, Burst: 10},
			"ui":           {Rate: 30, Burst: 60},
			"api":          {Rate: 30, Burst: 60},
			"enroll":       {Rate: 2, Burst: 5},
			"agent_import": {Rate: 2, Burst: 5},
			"agent_poll":   {Rate: 60, Burst: 120},
		},
		MaxEntriesPerShard: 65536,
		Shards:             4,
	}
}

// Limiter is the public API the middleware calls.
type Limiter struct {
	cfg    Config
	shards []*shard
}

// New builds a Limiter. Returns nil when cfg.Enabled is false so the
// middleware can short-circuit.
func New(cfg Config) *Limiter {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Shards <= 0 {
		cfg.Shards = 4
	}
	if cfg.MaxEntriesPerShard <= 0 {
		cfg.MaxEntriesPerShard = 65536
	}
	if cfg.Groups == nil {
		cfg.Groups = Default().Groups
	}
	l := &Limiter{cfg: cfg, shards: make([]*shard, cfg.Shards)}
	for i := range l.shards {
		l.shards[i] = newShard(cfg.MaxEntriesPerShard)
	}
	return l
}

// Allow reports whether a request from ip in route-group should be
// served. Returns the bucket's reservation delay so callers can set
// Retry-After. delay == 0 means the request was admitted.
func (l *Limiter) Allow(ip, group string) (allowed bool, retryAfter time.Duration) {
	if l == nil {
		return true, 0
	}
	gc, ok := l.cfg.Groups[group]
	if !ok {
		return true, 0
	}

	key := group + "|" + ip
	sh := l.shards[shardIndex(key, len(l.shards))]
	lim := sh.get(key, gc)

	r := lim.ReserveN(time.Now(), 1)
	if !r.OK() {
		return false, time.Second
	}
	delay := r.DelayFrom(time.Now())
	if delay <= 0 {
		return true, 0
	}
	r.Cancel()
	return false, ceilDuration(delay)
}

// ClientIP returns the effective IP for the request. When the limiter
// is configured to trust X-Forwarded-For, the rightmost address wins:
// that entry was appended by the reverse proxy in front of this server,
// while everything to its left arrived in the client's own header and
// is attacker-controlled. Entries left of the rightmost are never
// consulted — falling back leftward on a parse failure would let a
// client choose its own rate-limit key with "spoofed, garbage". If the
// rightmost entry does not parse, or trust_proxy_header is off,
// RemoteAddr is used.
func (l *Limiter) ClientIP(r *http.Request) string {
	if l != nil && l.cfg.TrustProxyHeader {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if ip := net.ParseIP(last); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// MaskIP collapses an IP to its rate-limit-friendly prefix so audit
// entries don't explode under a sustained attack. /24 for IPv4, /64
// for IPv6.
func MaskIP(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	if v4 := ip.To4(); v4 != nil {
		return (&net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

func ceilDuration(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	// Round up to the next whole second so Retry-After is integer
	// friendly (RFC 7231 §7.1.3 allows seconds or HTTP-date).
	whole := d.Round(time.Second)
	if whole < d {
		whole += time.Second
	}
	return whole
}

// --- internal shard / LRU ------------------------------------------------

type shard struct {
	mu     sync.Mutex
	max    int
	lookup map[string]*list.Element
	lru    *list.List
}

type entry struct {
	key string
	lim *rate.Limiter
}

func newShard(maxEntries int) *shard {
	return &shard{max: maxEntries, lookup: make(map[string]*list.Element), lru: list.New()}
}

func (s *shard) get(key string, gc GroupConfig) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.lookup[key]; ok {
		s.lru.MoveToBack(el)
		return el.Value.(*entry).lim
	}
	lim := rate.NewLimiter(rate.Limit(gc.Rate), gc.Burst)
	el := s.lru.PushBack(&entry{key: key, lim: lim})
	s.lookup[key] = el
	if s.lru.Len() > s.max {
		oldest := s.lru.Front()
		if oldest != nil {
			s.lru.Remove(oldest)
			delete(s.lookup, oldest.Value.(*entry).key)
		}
	}
	return lim
}

func shardIndex(key string, shards int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()) % shards
}

// WriteRetryAfter writes the standard 429 response (Retry-After header
// and a tiny body) so callers don't repeat the boilerplate.
func WriteRetryAfter(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(retryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
}

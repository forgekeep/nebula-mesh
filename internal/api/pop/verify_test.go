package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	agentpop "github.com/juev/nebula-mesh/internal/agent/pop"
	corepop "github.com/juev/nebula-mesh/internal/pop"
)

func TestVerify_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	canonical := corepop.CanonicalString("GET", "/p", "h", "ts", "n")
	sig, err := agentpop.Sign(priv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, canonical, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_TamperedCanonical(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	canonical := corepop.CanonicalString("GET", "/p", "h", "ts", "n")
	sig, _ := agentpop.Sign(priv, canonical)
	if err := Verify(pub, canonical+"x", sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	canonical := corepop.CanonicalString("GET", "/p", "h", "ts", "n")
	sig, _ := agentpop.Sign(priv, canonical)
	if err := Verify(otherPub, canonical, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerify_BadKeyLength(t *testing.T) {
	if err := Verify(make([]byte, 5), "msg", []byte("sig")); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerify_BadSignatureLength(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(pub, "msg", []byte("short")); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestNonceCache_AcceptsOnce(t *testing.T) {
	c := NewNonceCache(NonceCacheConfig{Capacity: 16, IdleTTL: time.Minute, Now: time.Now})
	if !c.SeenOrAdd("host1", "nonceA") {
		t.Error("first SeenOrAdd returned false (must be true = added)")
	}
	if c.SeenOrAdd("host1", "nonceA") {
		t.Error("replay returned true (must be false = already seen)")
	}
	// Different host + same nonce is still independent (we key by both).
	if !c.SeenOrAdd("host2", "nonceA") {
		t.Error("different host nonceA must be accepted")
	}
}

func TestNonceCache_EvictsBySize(t *testing.T) {
	c := NewNonceCache(NonceCacheConfig{Capacity: 2, IdleTTL: time.Hour, Now: time.Now})
	c.SeenOrAdd("h", "a")
	c.SeenOrAdd("h", "b")
	c.SeenOrAdd("h", "c") // evicts "a"
	if !c.SeenOrAdd("h", "a") {
		t.Error("nonce a should have been evicted and acceptable again")
	}
}

func TestNonceCache_EvictsByIdle(t *testing.T) {
	now := time.Unix(0, 0)
	c := NewNonceCache(NonceCacheConfig{Capacity: 16, IdleTTL: 10 * time.Minute, Now: func() time.Time { return now }})
	c.SeenOrAdd("h", "a")
	now = now.Add(11 * time.Minute)
	if !c.SeenOrAdd("h", "a") {
		t.Error("nonce should have been evicted after idle TTL")
	}
}

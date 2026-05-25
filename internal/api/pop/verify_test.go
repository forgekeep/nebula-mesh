package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	agentpop "github.com/forgekeep/nebula-mesh/internal/agent/pop"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
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

package rekeytoken

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

var domain = []byte("nebula-mesh-rekey-token-v1\x00")

func Seal(hostPublicKey []byte, token string) (string, error) {
	if len(hostPublicKey) != curve25519.PointSize || token == "" {
		return "", errors.New("invalid rekey token input")
	}
	plaintext := append(append(make([]byte, 0, len(domain)+len(token)), domain...), token...)
	defer clear(plaintext)
	sealed, err := box.SealAnonymous(nil, plaintext, (*[32]byte)(hostPublicKey), rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func Open(hostPrivateKey []byte, encoded string) (string, error) {
	if len(hostPrivateKey) != curve25519.ScalarSize || encoded == "" {
		return "", errors.New("invalid rekey token input")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("invalid rekey token encoding")
	}
	hostPublicKey, err := curve25519.X25519(hostPrivateKey, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	plaintext, ok := box.OpenAnonymous(nil, sealed, (*[32]byte)(hostPublicKey), (*[32]byte)(hostPrivateKey))
	if !ok {
		return "", errors.New("cannot decrypt rekey token")
	}
	defer clear(plaintext)
	if !bytes.HasPrefix(plaintext, domain) || len(plaintext) == len(domain) {
		return "", errors.New("invalid rekey token purpose")
	}
	return string(plaintext[len(domain):]), nil
}

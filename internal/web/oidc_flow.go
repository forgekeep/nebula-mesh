package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	oidcFlowCookie    = "nebula_oidc_flow"
	oidcFlowTTL       = 10 * time.Minute
	oidcFlowCookieMax = 512
)

var errInvalidOIDCFlow = errors.New("invalid oidc state")

type oidcFlow struct {
	State     string
	Nonce     string
	Verifier  string
	ExpiresAt int64
}

func newOIDCFlowCipher() (cipher.AEAD, error) {
	// A restart invalidates unfinished logins, as it did with the pending map.
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func newOIDCFlow(now time.Time) (oidcFlow, error) {
	var random [64]byte
	if _, err := rand.Read(random[:]); err != nil {
		return oidcFlow{}, err
	}
	defer clear(random[:])
	return oidcFlow{
		State:     base64.RawURLEncoding.EncodeToString(random[:16]),
		Nonce:     base64.RawURLEncoding.EncodeToString(random[16:32]),
		Verifier:  base64.RawURLEncoding.EncodeToString(random[32:]),
		ExpiresAt: now.Add(oidcFlowTTL).Unix(),
	}, nil
}

func (o *OIDC) flowCookieName() string {
	if o.cookieSecure {
		return "__Host-" + oidcFlowCookie
	}
	return oidcFlowCookie
}

func (o *OIDC) setFlowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows the resolved server setting.
		Name:     o.flowCookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   o.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (o *OIDC) sealFlow(flow oidcFlow) (string, error) {
	data, err := json.Marshal(flow)
	if err != nil {
		return "", err
	}
	defer clear(data)
	sealed := o.flowCipher.Seal(nil, nil, data, []byte(o.flowCookieName())) // #nosec G407 -- GCM generates the nonce internally.
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (o *OIDC) readFlow(r *http.Request, state string, now time.Time) (oidcFlow, error) {
	cookies := r.CookiesNamed(o.flowCookieName())
	if o.flowCipher == nil || len(cookies) != 1 || len(cookies[0].Value) > oidcFlowCookieMax || state == "" {
		return oidcFlow{}, errInvalidOIDCFlow
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cookies[0].Value)
	if err != nil {
		return oidcFlow{}, errInvalidOIDCFlow
	}
	data, err := o.flowCipher.Open(nil, nil, sealed, []byte(o.flowCookieName()))
	if err != nil {
		return oidcFlow{}, errInvalidOIDCFlow
	}
	defer clear(data)
	var flow oidcFlow
	if err := json.Unmarshal(data, &flow); err != nil || flow.ExpiresAt <= now.Unix() ||
		subtle.ConstantTimeCompare([]byte(flow.State), []byte(state)) != 1 {
		return oidcFlow{}, errInvalidOIDCFlow
	}
	return flow, nil
}

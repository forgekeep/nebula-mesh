package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

const (
	oidcOffboardingPath      = "/ui/oidc/offboard"
	oidcOffboardingSignature = "X-Nebula-Offboarding-Signature"
	oidcOffboardingMaxBody   = 4096
	oidcOffboardingWindow    = 5 * time.Minute
	oidcOffboardingClockSkew = 30 * time.Second
)

type oidcOffboardingRequest struct {
	EventID  string `json:"event_id"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	Subject  string `json:"subject"`
	IssuedAt int64  `json:"issued_at"`
}

// WithOIDCOffboarding installs a revocation-only endpoint for the configured IdP.
func (w *Web) WithOIDCOffboarding(encodedKey string) error {
	if w.oidc == nil {
		return errors.New("NEBULA_MGMT_OIDC_OFFBOARDING_KEY requires enabled OIDC")
	}
	key, err := hex.DecodeString(encodedKey)
	if err != nil || len(key) != sha256.Size {
		clear(key)
		return errors.New("NEBULA_MGMT_OIDC_OFFBOARDING_KEY must encode 32 bytes as hex")
	}
	w.router.With(w.rateLimitMiddleware("auth")).Post(oidcOffboardingPath, w.oidcOffboardingHandler(key))
	return nil
}

func (w *Web) oidcOffboardingHandler(key []byte) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !w.secretIngress.Allows(r) {
			http.Error(rw, "OIDC offboarding requires a protected transport", http.StatusUpgradeRequired)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(rw, "expected application/json", http.StatusUnsupportedMediaType)
			return
		}
		signatures := r.Header.Values(oidcOffboardingSignature)
		if len(signatures) != 1 {
			http.Error(rw, "invalid offboarding signature", http.StatusUnauthorized)
			return
		}
		digest, ok := strings.CutPrefix(signatures[0], "sha256=")
		if !ok || len(digest) != sha256.Size*2 {
			http.Error(rw, "invalid offboarding signature", http.StatusUnauthorized)
			return
		}
		provided, err := hex.DecodeString(digest)
		if err != nil {
			http.Error(rw, "invalid offboarding signature", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, oidcOffboardingMaxBody))
		if err != nil {
			var sizeErr *http.MaxBytesError
			if errors.As(err, &sizeErr) {
				http.Error(rw, "offboarding event too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(rw, "invalid offboarding event", http.StatusBadRequest)
			}
			return
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(body)
		if !hmac.Equal(provided, mac.Sum(nil)) {
			http.Error(rw, "invalid offboarding signature", http.StatusUnauthorized)
			return
		}
		var event oidcOffboardingRequest
		if err := json.Unmarshal(body, &event); err != nil || event.Issuer != w.oidc.cfg.Issuer ||
			event.Audience != w.oidc.cfg.ClientID || strings.TrimSpace(event.Subject) == "" ||
			len(event.Subject) > 255 || strings.TrimSpace(event.EventID) == "" || len(event.EventID) > 128 {
			http.Error(rw, "invalid offboarding event", http.StatusBadRequest)
			return
		}
		issued := time.Unix(event.IssuedAt, 0)
		if !validOffboardingTime(issued, time.Now()) {
			http.Error(rw, "expired or future offboarding event", http.StatusBadRequest)
			return
		}
		proof := store.OIDCOffboardingEvent{
			Digest:    sha256.Sum256([]byte(event.EventID)),
			ExpiresAt: issued.Add(oidcOffboardingWindow),
		}
		if err := w.store.RevokeOIDCOperator(r.Context(), event.Issuer, event.Subject, &proof); err != nil {
			w.logger.Error("apply OIDC offboarding event", "error", err)
			http.Error(rw, "internal error", http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(http.StatusNoContent)
	}
}

func validOffboardingTime(issued, now time.Time) bool {
	return issued.After(now.Add(-oidcOffboardingWindow)) && !issued.After(now.Add(oidcOffboardingClockSkew))
}

// Only complete claims can confirm loss of every configured route to admission.
func (o *OIDC) confirmedGroupLoss(token *oidc.IDToken, claims map[string]any, groupsClaim, email string) bool {
	if len(o.cfg.AllowedGroups) == 0 || token.Subject == "" || !validOffboardingTime(token.IssuedAt, time.Now()) {
		return false
	}
	if len(o.cfg.AllowedEmails) != 0 && (email == "" || !parseEmailVerified(claims["email_verified"])) {
		return false
	}
	switch groups := claims[groupsClaim].(type) {
	case []any:
		for _, group := range groups {
			if _, ok := group.(string); !ok {
				return false
			}
		}
		return true
	case string:
		return true
	default:
		return false
	}
}

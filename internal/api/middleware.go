package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/juev/nebula-mesh/internal/store"
)

// maxBodySize returns middleware that limits the size of request bodies.
func maxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerAuth returns middleware that authenticates the Bearer token against
// the DB-backed operator API keys. The legacyKey (if non-empty) is accepted
// as a fallback for backward compatibility with the config-only api_key —
// in that case no operator is attached to the context and ActorName falls
// back to "legacy-admin".
func bearerAuth(s store.Store, legacyKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				writeError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			token := strings.TrimPrefix(auth, "Bearer ")
			if token == auth || token == "" {
				writeError(w, http.StatusUnauthorized, "invalid API key")
				return
			}

			// Hash and look up in operator_api_keys.
			sum := sha256.Sum256([]byte(token))
			hash := hex.EncodeToString(sum[:])
			op, key, err := s.GetOperatorByAPIKeyHash(r.Context(), hash)
			switch {
			case err == nil:
				// Best-effort last_used_at update; ignore failure.
				if err := s.TouchOperatorAPIKey(r.Context(), key.ID, time.Now()); err != nil {
					slog.Debug("touch api key", "error", err)
				}
				next.ServeHTTP(w, r.WithContext(withActor(r.Context(), op)))
				return
			case !errors.Is(err, store.ErrNotFound):
				slog.Error("auth lookup", "error", err)
				writeError(w, http.StatusInternalServerError, "auth lookup failed")
				return
			}

			// Fallback: legacy config-file API key.
			if legacyKey != "" && token == legacyKey {
				next.ServeHTTP(w, r)
				return
			}

			writeError(w, http.StatusUnauthorized, "invalid API key")
		})
	}
}

// requestLogger returns middleware that logs requests.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.status,
				"duration", time.Since(start),
			)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

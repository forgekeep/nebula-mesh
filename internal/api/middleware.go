package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/juev/nebula-mesh/internal/ratelimit"
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
// the DB-backed operator API keys and attaches the matching operator to the
// request context. Requests that pass through are guaranteed to have a
// non-nil ActorOf(ctx).
func bearerAuth(s store.Store) func(http.Handler) http.Handler {
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

// rateLimitMiddleware applies the per-IP token-bucket limiter for the
// named route group. When the server has no limiter wired up (Enabled=
// false in config) requests pass through unchanged.
func (s *Server) rateLimitMiddleware(group string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.limiter == nil {
				next.ServeHTTP(w, r)
				return
			}
			ip := s.limiter.ClientIP(r)
			ok, retry := s.limiter.Allow(ip, group)
			if !ok {
				ratelimit.WriteRetryAfter(w, retry)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// metricsMiddleware records every served HTTP request and its server-side
// latency on the server's private Prometheus registry. The route label is the
// chi route pattern (e.g. /api/v1/hosts/{id}) rather than the raw URL, so the
// label cardinality stays bounded by the number of declared routes.
func (s *Server) metricsMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)

			if s.metrics == nil {
				return
			}
			route := chi.RouteContext(r.Context()).RoutePattern()
			if route == "" {
				route = r.URL.Path
			}
			s.metrics.httpRequests.WithLabelValues(r.Method, route, strconv.Itoa(ww.status)).Inc()
			s.metrics.httpDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		})
	}
}

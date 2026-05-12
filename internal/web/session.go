package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "nebula_session"
	sessionDuration   = 24 * time.Hour
)

// SessionManager handles DB-backed cookie sessions for operator users.
type SessionManager struct {
	store store.Store
}

// NewSessionManager creates a new session manager backed by the given store.
func NewSessionManager(s store.Store) *SessionManager {
	return &SessionManager{store: s}
}

// Login looks up the operator by username, verifies the password (bcrypt),
// records a session, sets the cookie, and returns the operator. The boolean
// is true when the credentials were valid.
func (sm *SessionManager) Login(w http.ResponseWriter, r *http.Request, username, password string) (*models.Operator, bool, error) {
	if username == "" || password == "" {
		return nil, false, nil
	}
	op, err := sm.store.GetOperatorByUsername(r.Context(), username)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("lookup operator: %w", err)
	}
	if op.Status != models.OperatorStatusActive {
		return nil, false, nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(password)); err != nil {
		return nil, false, nil
	}

	token, err := generateToken()
	if err != nil {
		return nil, false, err
	}
	expires := time.Now().Add(sessionDuration)
	if err := sm.store.CreateOperatorSession(r.Context(), &models.OperatorSession{
		Token:      token,
		OperatorID: op.ID,
		ExpiresAt:  expires,
	}); err != nil {
		return nil, false, fmt.Errorf("create session: %w", err)
	}
	if err := sm.store.UpdateOperatorLastLogin(r.Context(), op.ID, time.Now()); err != nil {
		slog.Debug("update last login", "error", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	return op, true, nil
}

// Logout invalidates the session cookie and removes the DB record.
func (sm *SessionManager) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		if err := sm.store.DeleteOperatorSession(r.Context(), cookie.Value); err != nil {
			slog.Debug("delete session", "error", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// CurrentOperator returns the operator owning the request's session cookie,
// or nil if there is no valid session. A disabled operator's session is also
// treated as invalid.
func (sm *SessionManager) CurrentOperator(r *http.Request) *models.Operator {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	op, err := sm.store.GetOperatorBySession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}
	return op
}

// IsAuthenticated reports whether the request carries a valid session.
func (sm *SessionManager) IsAuthenticated(r *http.Request) bool {
	return sm.CurrentOperator(r) != nil
}

// StartCleanup runs a background goroutine that periodically deletes expired
// sessions from the store. It stops when ctx is cancelled.
func (sm *SessionManager) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sm.store.DeleteExpiredOperatorSessions(ctx, time.Now()); err != nil {
					slog.Debug("cleanup expired sessions", "error", err)
				}
			}
		}
	}()
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

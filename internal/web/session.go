package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName = "nebula_session"
	sessionDuration   = 24 * time.Hour
)

type session struct {
	expiresAt time.Time
}

// SessionManager handles cookie-based sessions.
type SessionManager struct {
	password string
	mu       sync.RWMutex
	sessions map[string]session
}

// NewSessionManager creates a new session manager.
func NewSessionManager(password string) *SessionManager {
	return &SessionManager{
		password: password,
		sessions: make(map[string]session),
	}
}

// Login validates the password and creates a session cookie.
func (sm *SessionManager) Login(w http.ResponseWriter, password string) (bool, error) {
	if password != sm.password {
		return false, nil
	}

	token, err := generateToken()
	if err != nil {
		return false, err
	}
	sm.mu.Lock()
	sm.sessions[token] = session{expiresAt: time.Now().Add(sessionDuration)}
	sm.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	return true, nil
}

// Logout invalidates the session.
func (sm *SessionManager) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sm.mu.Lock()
		delete(sm.sessions, cookie.Value)
		sm.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// IsAuthenticated checks if the request has a valid session.
func (sm *SessionManager) IsAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessions[cookie.Value]
	if !ok || time.Now().After(sess.expiresAt) {
		delete(sm.sessions, cookie.Value)
		return false
	}
	return true
}

// StartCleanup runs a background goroutine that periodically removes expired sessions.
// It stops when ctx is cancelled.
func (sm *SessionManager) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sm.removeExpired()
			}
		}
	}()
}

func (sm *SessionManager) removeExpired() {
	now := time.Now()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for token, sess := range sm.sessions {
		if now.After(sess.expiresAt) {
			delete(sm.sessions, token)
		}
	}
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

package web

import (
	"crypto/rand"
	"encoding/hex"
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
func (sm *SessionManager) Login(w http.ResponseWriter, password string) bool {
	if password != sm.password {
		return false
	}

	token := generateToken()
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
	return true
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

	sm.mu.RLock()
	sess, ok := sm.sessions[cookie.Value]
	sm.mu.RUnlock()

	if !ok || time.Now().After(sess.expiresAt) {
		if ok {
			sm.mu.Lock()
			delete(sm.sessions, cookie.Value)
			sm.mu.Unlock()
		}
		return false
	}
	return true
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

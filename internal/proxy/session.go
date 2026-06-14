package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"
)

const ProxySessionCookieName = "odo_proxy_sid"

type SessionStore struct {
	mu          sync.Mutex
	sessions    map[string]*proxySession
	idleTimeout time.Duration
	lastCleanup time.Time
}

type proxySession struct {
	jar        *cookiejar.Jar
	lastAccess time.Time
}

type SessionInfo struct {
	ID      string
	Jar     *cookiejar.Jar
	Created bool
}

func NewSessionStore(idleTimeout time.Duration) *SessionStore {
	if idleTimeout <= 0 {
		idleTimeout = 2 * time.Hour
	}
	return &SessionStore{
		sessions:    map[string]*proxySession{},
		idleTimeout: idleTimeout,
	}
}

func (s *SessionStore) GetOrCreate(r *http.Request, w http.ResponseWriter) SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.cleanupLocked(now)

	id := ""
	if cookie, err := r.Cookie(ProxySessionCookieName); err == nil {
		id = cookie.Value
	}
	if id != "" {
		if session, ok := s.sessions[id]; ok {
			session.lastAccess = now
			return SessionInfo{ID: id, Jar: session.jar, Created: false}
		}
	}

	jar, _ := cookiejar.New(nil)
	id = randomSessionID()
	s.sessions[id] = &proxySession{jar: jar, lastAccess: now}
	http.SetCookie(w, &http.Cookie{
		Name:     ProxySessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
	return SessionInfo{ID: id, Jar: jar, Created: true}
}

func (s *SessionStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(time.Now())
	return len(s.sessions)
}

func (s *SessionStore) cleanupLocked(now time.Time) {
	if !s.lastCleanup.IsZero() && now.Sub(s.lastCleanup) < time.Minute {
		return
	}
	for id, session := range s.sessions {
		if now.Sub(session.lastAccess) > s.idleTimeout {
			delete(s.sessions, id)
		}
	}
	s.lastCleanup = now
}

func randomSessionID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

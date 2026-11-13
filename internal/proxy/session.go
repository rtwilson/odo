package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"example.org/odo/internal/cookiepolicy"
)

const ProxySessionCookieName = "odo_proxy_sid"

type SessionStore struct {
	mu          sync.Mutex
	sessions    map[string]*proxySession
	idleTimeout time.Duration
	lastCleanup time.Time
	random      io.Reader
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
		random:      rand.Reader,
	}
}

func (s *SessionStore) GetOrCreate(r *http.Request, w http.ResponseWriter) (SessionInfo, error) {
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
			return SessionInfo{ID: id, Jar: session.jar, Created: false}, nil
		}
	}

	id, err := randomSessionID(s.random)
	if err != nil {
		return SessionInfo{}, err
	}
	jar, _ := cookiejar.New(nil)
	s.sessions[id] = &proxySession{jar: jar, lastAccess: now}
	http.SetCookie(w, cookiepolicy.Apply(r, &http.Cookie{
		Name:     ProxySessionCookieName,
		Value:    id,
		HttpOnly: true,
		MaxAge:   int(s.idleTimeout / time.Second),
		Expires:  now.Add(s.idleTimeout),
	}))
	return SessionInfo{ID: id, Jar: jar, Created: true}, nil
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

func randomSessionID(random io.Reader) (string, error) {
	buf := make([]byte, 32)
	// Read from the cryptographic reader directly so read failures propagate
	// without a predictable fallback. Tests can supply a reader on one store.
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", fmt.Errorf("generate proxy session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

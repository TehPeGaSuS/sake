package webadmin

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	loginMaxAttempts = 5
	loginWindow      = 5 * time.Minute
	loginLockout     = 1 * time.Minute
)

// loginLimiter tracks failed login attempts per source IP + username pair,
// so a distributed brute-force sweep across usernames from one IP is
// throttled the same as repeated attempts against a single account.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempts
}

type loginAttempts struct {
	count      int
	windowFrom time.Time
	lockedTil  time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string]*loginAttempts)}
}

func loginKey(r *http.Request, username string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host + "|" + username
}

// allow reports whether a login attempt for this key may proceed.
func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.attempts[key]
	if !ok {
		return true
	}
	if !a.lockedTil.IsZero() && time.Now().Before(a.lockedTil) {
		return false
	}
	return true
}

func (l *loginLimiter) recordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	a, ok := l.attempts[key]
	if !ok || now.Sub(a.windowFrom) > loginWindow {
		a = &loginAttempts{windowFrom: now}
		l.attempts[key] = a
	}
	a.count++
	if a.count >= loginMaxAttempts {
		a.lockedTil = now.Add(loginLockout)
	}
}

func (l *loginLimiter) recordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

// Package webadmin implements a self-service web administration panel for
// sake, in the spirit of ZNC's webadmin module: every user can manage their
// own account and networks, and users with the Admin flag can additionally
// manage any other user.
package webadmin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TehPeGaSuS/sake/auth"
	"github.com/TehPeGaSuS/sake/database"
)

const sessionCookieName = "sake_admin_session"
const sessionTTL = 24 * time.Hour

// Handler serves the self-service web admin panel. It is a pure consumer of
// database.Database and auth.Authenticator: it does not reach into the
// running Server/user state, so it can be mounted on any existing HTTP
// listener (e.g. alongside /socket, /uploads) without touching soju's core.
type Handler struct {
	DB   database.Database
	Auth *auth.Authenticator

	secret []byte // HMAC key for session/CSRF signing, persisted across restarts
	mux    *http.ServeMux

	limiter *loginLimiter
}

// New creates the web admin handler. secretPath is where the HMAC signing
// key is persisted (e.g. alongside the config file); it is generated on
// first use and reused afterwards so restarts don't invalidate every open
// session. If secretPath is empty, a key is generated in memory and
// sessions won't survive a restart.
func New(db database.Database, authr *auth.Authenticator, secretPath string) *Handler {
	secret, err := loadOrCreateSecret(secretPath)
	if err != nil {
		panic("webadmin: failed to load or create session secret: " + err.Error())
	}

	h := &Handler{DB: db, Auth: authr, secret: secret, limiter: newLoginLimiter()}
	h.mux = http.NewServeMux()
	h.routes()
	return h
}

func loadOrCreateSecret(path string) ([]byte, error) {
	if path == "" {
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		return secret, err
	}

	if b, err := os.ReadFile(path); err == nil {
		secret, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err == nil && len(secret) == 32 {
			return secret, nil
		}
		// fall through and regenerate on any corruption
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(secret)+"\n"), 0600); err != nil {
		return nil, err
	}
	return secret, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	h.mux.HandleFunc("GET /admin/login", h.handleLoginForm)
	h.mux.HandleFunc("POST /admin/login", h.handleLogin)
	h.mux.HandleFunc("POST /admin/logout", h.requireLogin(h.handleLogout))

	h.mux.HandleFunc("GET /admin/", h.requireLogin(h.handleDashboard))

	h.mux.HandleFunc("GET /admin/account", h.requireLogin(h.handleAccountForm))
	h.mux.HandleFunc("POST /admin/account", h.requireLogin(h.handleAccountSave))

	h.mux.HandleFunc("GET /admin/networks/new", h.requireLogin(h.handleNetworkForm))
	h.mux.HandleFunc("GET /admin/networks/{id}", h.requireLogin(h.handleNetworkForm))
	h.mux.HandleFunc("POST /admin/networks/{id}", h.requireLogin(h.handleNetworkSave))
	h.mux.HandleFunc("POST /admin/networks/{id}/delete", h.requireLogin(h.handleNetworkDelete))

	h.mux.HandleFunc("GET /admin/networks/{netID}/channels/new", h.requireLogin(h.handleChannelForm))
	h.mux.HandleFunc("GET /admin/networks/{netID}/channels/{id}", h.requireLogin(h.handleChannelForm))
	h.mux.HandleFunc("POST /admin/networks/{netID}/channels/{id}", h.requireLogin(h.handleChannelSave))
	h.mux.HandleFunc("POST /admin/networks/{netID}/channels/{id}/delete", h.requireLogin(h.handleChannelDelete))

	h.mux.HandleFunc("GET /admin/users", h.requireAdmin(h.handleUserList))
	h.mux.HandleFunc("GET /admin/users/new", h.requireAdmin(h.handleUserForm))
	h.mux.HandleFunc("GET /admin/users/{username}", h.requireAdmin(h.handleUserForm))
	h.mux.HandleFunc("POST /admin/users/{username}", h.requireAdmin(h.handleUserSave))
	h.mux.HandleFunc("POST /admin/users/{username}/delete", h.requireAdmin(h.handleUserDelete))
}

// --- session handling ---

type session struct {
	Username string
}

func (h *Handler) signValue(v string) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(v))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, username string) {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := fmt.Sprintf("%s|%d", username, exp)
	sig := h.signValue(payload)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Expires:  time.Unix(exp, 0),
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (h *Handler) session(r *http.Request) *session {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return nil
	}
	rawPayload, sig := parts[0], parts[1]
	if !hmac.Equal([]byte(sig), []byte(h.signValue(string(mustDecode(rawPayload))))) {
		return nil
	}
	payload := string(mustDecode(rawPayload))
	fields := strings.SplitN(payload, "|", 2)
	if len(fields) != 2 {
		return nil
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil
	}
	return &session{Username: fields[0]}
}

func mustDecode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// --- CSRF protection ---
//
// Sessions are stateless signed cookies, so CSRF tokens are derived
// deterministically from the session cookie's own value via a distinct HMAC
// purpose. A cross-site request can trigger the cookie to be sent, but
// can't read it (HttpOnly) or otherwise learn the derived token, so it
// can't fill in a matching hidden form field.

func (h *Handler) csrfToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return h.signValue("csrf|" + c.Value)
}

func (h *Handler) checkCSRF(r *http.Request) error {
	want := h.csrfToken(r)
	got := r.FormValue("csrf")
	if want == "" || got == "" || !hmac.Equal([]byte(want), []byte(got)) {
		return errors.New("invalid or missing CSRF token")
	}
	return nil
}

// currentUser resolves the logged-in session to a live database.User record.
func (h *Handler) currentUser(r *http.Request) (*database.User, error) {
	sess := h.session(r)
	if sess == nil {
		return nil, errors.New("not logged in")
	}
	u, err := h.DB.GetUser(r.Context(), sess.Username)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (h *Handler) requireLogin(next func(w http.ResponseWriter, r *http.Request, actor *database.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, err := h.currentUser(r)
		if err != nil || !actor.Enabled {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			if err := h.checkCSRF(r); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
		next(w, r, actor)
	}
}

func (h *Handler) requireAdmin(next func(w http.ResponseWriter, r *http.Request, actor *database.User)) http.HandlerFunc {
	return h.requireLogin(func(w http.ResponseWriter, r *http.Request, actor *database.User) {
		if !actor.Admin {
			http.Error(w, "forbidden: admin privileges required", http.StatusForbidden)
			return
		}
		next(w, r, actor)
	})
}

// authorize implements the "usual admin special cases": an actor may always
// operate on their own account/networks, and an admin may operate on anyone's.
func authorize(actor *database.User, targetUsername string) error {
	if actor.Admin || actor.Username == targetUsername {
		return nil
	}
	return errors.New("forbidden: you may only manage your own account")
}

// errNotFound is a sentinel used by resolver helpers (e.g.
// resolveNetworkForChannels) to distinguish "doesn't exist" from
// authorize's "forbidden" error; see writeResolveError.
var errNotFound = errors.New("not found")

func writeResolveError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errNotFound) {
		http.NotFound(w, r)
		return
	}
	http.Error(w, err.Error(), http.StatusForbidden)
}

// checkPassword delegates to the configured auth driver (internal DB, PAM,
// HTTP, OAuth2...) so the web login honors the same policy as SASL PLAIN.
func (h *Handler) checkPassword(ctx context.Context, username, password string) error {
	if h.Auth == nil || h.Auth.Plain == nil {
		return errors.New("password authentication is not configured")
	}
	return h.Auth.Plain.AuthPlain(ctx, h.DB, username, password)
}

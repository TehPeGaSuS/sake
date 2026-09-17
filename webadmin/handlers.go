package webadmin

import (
	"embed"
	"html/template"
	"net/http"
	"strconv"

	"github.com/TehPeGaSuS/sake/database"
)

//go:embed templates/*.html
var templateFS embed.FS

// Each page file defines a template named "body", so pages must be parsed
// as separate template sets (each paired with layout.html) rather than all
// together - otherwise the "body" definitions collide and only one survives.
var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{
		"login.html", "dashboard.html", "account.html",
		"network.html", "users.html", "user.html",
	} {
		pages[name] = template.Must(template.New("layout").ParseFS(templateFS, "templates/layout.html", "templates/"+name))
	}
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name, title string, actor *database.User, errMsg string, extra map[string]any) {
	data := map[string]any{
		"Title": title,
		"Actor": actor,
		"Error": errMsg,
		"CSRF":  h.csrfToken(r),
	}
	for k, v := range extra {
		data[k] = v
	}
	t, ok := pages[name]
	if !ok {
		http.Error(w, "unknown template "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// --- login/logout ---

func (h *Handler) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if h.session(r) != nil {
		http.Redirect(w, r, "/admin/", http.StatusFound)
		return
	}
	h.render(w, r, "login.html", "Log in", nil, "", nil)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	key := loginKey(r, username)

	if !h.limiter.allow(key) {
		h.render(w, r, "login.html", "Log in", nil, "Too many failed attempts, try again in a minute", nil)
		return
	}

	if err := h.checkPassword(r.Context(), username, password); err != nil {
		h.limiter.recordFailure(key)
		h.render(w, r, "login.html", "Log in", nil, "Invalid username or password", nil)
		return
	}

	u, err := h.DB.GetUser(r.Context(), username)
	if err != nil || !u.Enabled {
		h.limiter.recordFailure(key)
		h.render(w, r, "login.html", "Log in", nil, "This account is disabled", nil)
		return
	}

	h.limiter.recordSuccess(key)
	h.setSessionCookie(w, username)
	http.Redirect(w, r, "/admin/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request, actor *database.User) {
	h.clearSessionCookie(w)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

// --- dashboard ---

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request, actor *database.User) {
	networks, err := h.DB.ListNetworks(r.Context(), actor.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, r, "dashboard.html", "Dashboard", actor, "", map[string]any{
		"Networks": networks,
	})
}

// --- account (self-service, no admin special case needed: always self) ---

func (h *Handler) handleAccountForm(w http.ResponseWriter, r *http.Request, actor *database.User) {
	h.render(w, r, "account.html", "My account", actor, "", map[string]any{
		"User":           actor,
		"CanSetSourceIP": actor.Admin,
	})
}

func (h *Handler) handleAccountSave(w http.ResponseWriter, r *http.Request, actor *database.User) {
	actor.Nick = r.FormValue("nick")
	actor.Realname = r.FormValue("realname")
	if actor.Admin {
		actor.SourceIP = r.FormValue("source_ip")
	}
	if pw := r.FormValue("password"); pw != "" {
		if err := actor.SetPassword(pw); err != nil {
			h.render(w, r, "account.html", "My account", actor, err.Error(), map[string]any{"User": actor, "CanSetSourceIP": actor.Admin})
			return
		}
	}
	if err := h.DB.StoreUser(r.Context(), actor); err != nil {
		h.render(w, r, "account.html", "My account", actor, err.Error(), map[string]any{"User": actor, "CanSetSourceIP": actor.Admin})
		return
	}
	http.Redirect(w, r, "/admin/account", http.StatusFound)
}

// --- networks (self-service; admins may edit other users' via ?username=) ---

// targetForRequest resolves which user's networks this request operates on:
// the actor themself, unless an admin explicitly passed ?username=/username=
// to manage someone else's networks (mirrors ZNC's admin edit-other-user flow).
func (h *Handler) targetForRequest(r *http.Request, actor *database.User) (*database.User, error) {
	target := r.URL.Query().Get("username")
	if target == "" {
		target = r.FormValue("username")
	}
	if target == "" || target == actor.Username {
		return actor, nil
	}
	if err := authorize(actor, target); err != nil {
		return nil, err
	}
	return h.DB.GetUser(r.Context(), target)
}

func (h *Handler) handleNetworkForm(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, err := h.targetForRequest(r, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	net := &database.Network{}
	if idStr := r.PathValue("id"); idStr != "" && idStr != "new" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		networks, err := h.DB.ListNetworks(r.Context(), target.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		found := false
		for i := range networks {
			if networks[i].ID == id {
				net = &networks[i]
				found = true
				break
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
	}

	h.render(w, r, "network.html", "Network", actor, "", map[string]any{
		"Network":        net,
		"TargetUsername": target.Username,
		"CanSetAdvanced": actor.Admin,
	})
}

func (h *Handler) handleNetworkSave(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, err := h.targetForRequest(r, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	net := &database.Network{}
	if idStr := r.PathValue("id"); idStr != "" && idStr != "new" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		networks, err := h.DB.ListNetworks(r.Context(), target.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for i := range networks {
			if networks[i].ID == id {
				net = &networks[i]
				break
			}
		}
		if net.ID == 0 {
			http.NotFound(w, r)
			return
		}
	}

	net.Name = r.FormValue("name")
	net.Addr = r.FormValue("addr")
	net.Nick = r.FormValue("nick")
	net.Username = r.FormValue("username_irc")
	net.Realname = r.FormValue("realname")
	if pass := r.FormValue("pass"); pass != "" {
		net.Pass = pass
	}
	if u := r.FormValue("sasl_username"); u != "" {
		net.SASL.Mechanism = "PLAIN"
		net.SASL.Plain.Username = u
	}
	if p := r.FormValue("sasl_password"); p != "" {
		net.SASL.Mechanism = "PLAIN"
		net.SASL.Plain.Password = p
	}
	net.AutoAway = r.FormValue("auto_away") == "on"
	net.Enabled = r.FormValue("enabled") == "on"
	if actor.Admin {
		net.SourceIP = r.FormValue("source_ip")
		net.TLSInsecure = r.FormValue("tls_insecure") == "on"
	}

	if err := h.DB.StoreNetwork(r.Context(), target.ID, net); err != nil {
		h.render(w, r, "network.html", "Network", actor, err.Error(), map[string]any{
			"Network": net, "TargetUsername": target.Username, "CanSetAdvanced": actor.Admin,
		})
		return
	}

	redirect := "/admin/"
	if target.Username != actor.Username {
		redirect = "/admin/networks/" + strconv.FormatInt(net.ID, 10) + "?username=" + target.Username
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *Handler) handleNetworkDelete(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, err := h.targetForRequest(r, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Ensure the network actually belongs to the resolved target before deleting.
	networks, err := h.DB.ListNetworks(r.Context(), target.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	owned := false
	for _, n := range networks {
		if n.ID == id {
			owned = true
			break
		}
	}
	if !owned {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := h.DB.DeleteNetwork(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusFound)
}

// --- admin: user management ---

func (h *Handler) handleUserList(w http.ResponseWriter, r *http.Request, actor *database.User) {
	users, err := h.DB.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.render(w, r, "users.html", "Users", actor, "", map[string]any{"Users": users})
}

func (h *Handler) handleUserForm(w http.ResponseWriter, r *http.Request, actor *database.User) {
	u := database.NewUser("")
	existing := false
	if username := r.PathValue("username"); username != "" && username != "new" {
		found, err := h.DB.GetUser(r.Context(), username)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		u = found
		existing = true
	}
	h.render(w, r, "user.html", "User", actor, "", map[string]any{"User": u, "Existing": existing})
}

func (h *Handler) handleUserSave(w http.ResponseWriter, r *http.Request, actor *database.User) {
	usernameParam := r.PathValue("username")
	existing := usernameParam != "" && usernameParam != "new"

	u := database.NewUser("")
	if existing {
		found, err := h.DB.GetUser(r.Context(), usernameParam)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		u = found
	} else {
		u.Username = r.FormValue("username")
	}

	u.Nick = r.FormValue("nick")
	u.Realname = r.FormValue("realname")
	u.SourceIP = r.FormValue("source_ip")
	u.Admin = r.FormValue("admin") == "on"
	u.Enabled = r.FormValue("enabled") == "on"
	if mn, err := strconv.Atoi(r.FormValue("max_networks")); err == nil {
		u.MaxNetworks = mn
	}
	if pw := r.FormValue("password"); pw != "" {
		if err := u.SetPassword(pw); err != nil {
			h.render(w, r, "user.html", "User", actor, err.Error(), map[string]any{"User": u, "Existing": existing})
			return
		}
	} else if !existing {
		h.render(w, r, "user.html", "User", actor, "password is required for new users", map[string]any{"User": u, "Existing": existing})
		return
	}

	if err := h.DB.StoreUser(r.Context(), u); err != nil {
		h.render(w, r, "user.html", "User", actor, err.Error(), map[string]any{"User": u, "Existing": existing})
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (h *Handler) handleUserDelete(w http.ResponseWriter, r *http.Request, actor *database.User) {
	username := r.PathValue("username")
	if username == actor.Username {
		http.Error(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}
	u, err := h.DB.GetUser(r.Context(), username)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := h.DB.DeleteUser(r.Context(), u.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

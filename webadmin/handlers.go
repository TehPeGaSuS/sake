package webadmin

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	sake "github.com/TehPeGaSuS/sake"
	"github.com/TehPeGaSuS/sake/database"
)

//go:embed templates/*.html
var templateFS embed.FS

// Each page file defines a template named "body", so pages must be parsed
// as separate template sets (each paired with layout.html) rather than all
// together - otherwise the "body" definitions collide and only one survives.
var pages = map[string]*template.Template{}

// certFPHex strips the "sha-256:"/"sha-512:" storage prefix so the form
// field round-trips as plain hex, matching what a user would paste in.
func certFPHex(certFP string) string {
	if i := strings.IndexByte(certFP, ':'); i >= 0 {
		return certFP[i+1:]
	}
	return certFP
}

var templateFuncs = template.FuncMap{
	"certFPHex": certFPHex,
	// connectedFor formats how long ago a session connected, e.g. "3h12m".
	"connectedFor": func(t time.Time) string {
		return time.Since(t).Round(time.Second).String()
	},
}

func init() {
	for _, name := range []string{
		"login.html", "dashboard.html", "account.html",
		"network.html", "users.html", "user.html", "channel.html",
	} {
		pages[name] = template.Must(template.New("layout").Funcs(templateFuncs).ParseFS(templateFS, "templates/layout.html", "templates/"+name))
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

func (h *Handler) renderAccount(w http.ResponseWriter, r *http.Request, actor *database.User, errMsg string) {
	extra := map[string]any{
		"User":           actor,
		"CanSetSourceIP": actor.Admin,
	}
	if len(actor.SASLExternal.CertBlob) > 0 {
		sha256hex, sha512hex := certFingerprints(actor.SASLExternal.CertBlob)
		extra["DefaultCertSHA256"] = sha256hex
		extra["DefaultCertSHA512"] = sha512hex
	}
	if h.Srv != nil {
		sessions, err := h.Srv.ListSessions(r.Context(), actor.Username)
		if err != nil {
			if errMsg == "" {
				errMsg = "failed to list active sessions: " + err.Error()
			}
		} else {
			extra["Sessions"] = sessions
		}
	}
	h.render(w, r, "account.html", "My account", actor, errMsg, extra)
}

func (h *Handler) handleAccountForm(w http.ResponseWriter, r *http.Request, actor *database.User) {
	h.renderAccount(w, r, actor, "")
}

func (h *Handler) handleAccountSave(w http.ResponseWriter, r *http.Request, actor *database.User) {
	ctx := r.Context()
	orig := *actor

	actor.Nick = r.FormValue("nick")
	actor.Realname = r.FormValue("realname")
	if actor.Admin {
		actor.SourceIP = r.FormValue("source_ip")
	}

	var args []string
	args = flagIfChanged(args, "nick", orig.Nick, actor.Nick)
	args = flagIfChanged(args, "realname", orig.Realname, actor.Realname)
	if actor.Admin {
		args = flagIfChanged(args, "source-ip", orig.SourceIP, actor.SourceIP)
	}
	if pw := r.FormValue("password"); pw != "" {
		args = append(args, flagArg("password", pw))
	}
	if len(args) > 0 {
		if err := h.runAs(ctx, actor.Username, false, append([]string{"user", "update"}, args...)...); err != nil {
			h.renderAccount(w, r, actor, err.Error())
			return
		}
	}

	if r.FormValue("remove_default_cert") == "on" {
		if len(orig.SASLExternal.CertBlob) > 0 {
			if err := h.runAs(ctx, actor.Username, false, "certfp", "remove", "-default"); err != nil {
				h.renderAccount(w, r, actor, "default certificate: "+err.Error())
				return
			}
		}
	} else if pemText := strings.TrimSpace(r.FormValue("default_cert_pem")); pemText != "" {
		if err := h.runAs(ctx, actor.Username, false, "certfp", "import", "-default", "--", pemText); err != nil {
			h.renderAccount(w, r, actor, "default certificate: "+err.Error())
			return
		}
	}

	http.Redirect(w, r, "/admin/account", http.StatusFound)
}

func (h *Handler) handleSessionDisconnect(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, err := h.targetForRequest(r, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if h.Srv == nil {
		http.Error(w, "session management is not available", http.StatusServiceUnavailable)
		return
	}

	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := h.Srv.DisconnectSession(r.Context(), target.Username, id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	redirect := "/admin/account"
	if target.Username != actor.Username {
		redirect += "?username=" + target.Username
	}
	http.Redirect(w, r, redirect, http.StatusFound)
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

// findNetwork resolves idStr ("new" or a numeric id) to a network owned by
// targetID. It returns a zero-value Network for "new", or (nil, false, nil)
// if idStr doesn't parse or doesn't belong to targetID (caller should 404).
func (h *Handler) findNetwork(ctx context.Context, targetID int64, idStr string) (net *database.Network, ok bool, err error) {
	if idStr == "" || idStr == "new" {
		return &database.Network{}, true, nil
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return nil, false, nil
	}
	networks, err := h.DB.ListNetworks(ctx, targetID)
	if err != nil {
		return nil, false, err
	}
	for i := range networks {
		if networks[i].ID == id {
			return &networks[i], true, nil
		}
	}
	return nil, false, nil
}

func (h *Handler) handleNetworkForm(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, err := h.targetForRequest(r, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	net, ok, err := h.findNetwork(r.Context(), target.ID, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}

	h.renderNetwork(w, r, actor, net, target, "")
}

func (h *Handler) renderNetwork(w http.ResponseWriter, r *http.Request, actor *database.User, net *database.Network, target *database.User, errMsg string) {
	extra := map[string]any{
		"Network":        net,
		"TargetUsername": target.Username,
		"CanSetAdvanced": actor.Admin,
		"HasDefaultCert": len(target.SASLExternal.CertBlob) > 0,
	}
	if len(net.SASL.External.CertBlob) > 0 {
		sha256hex, sha512hex := certFingerprints(net.SASL.External.CertBlob)
		extra["ClientCertSHA256"] = sha256hex
		extra["ClientCertSHA512"] = sha512hex
	}
	if net.ID != 0 {
		channels, err := h.DB.ListChannels(r.Context(), net.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		extra["Channels"] = channels

		ignores, err := h.DB.ListIgnores(r.Context(), net.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		extra["Ignores"] = ignores
	}
	h.render(w, r, "network.html", "Network", actor, errMsg, extra)
}

func (h *Handler) handleNetworkSave(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, err := h.targetForRequest(r, actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	net, ok, err := h.findNetwork(r.Context(), target.ID, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	asAdmin := target.Username != actor.Username
	isNew := net.ID == 0
	orig := *net
	oldName := orig.GetName()

	// net becomes the desired state, so re-rendering on error keeps what
	// the user typed.
	net.Name = r.FormValue("name")
	net.Addr = r.FormValue("addr")
	net.Nick = r.FormValue("nick")
	net.Username = r.FormValue("username_irc")
	net.Realname = r.FormValue("realname")
	if pass := r.FormValue("pass"); pass != "" {
		net.Pass = pass
	}
	net.AutoAway = r.FormValue("auto_away") == "on"
	net.Enabled = r.FormValue("enabled") == "on"
	net.ConnectCommands = nil
	for _, line := range strings.Split(r.FormValue("connect_commands"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			net.ConnectCommands = append(net.ConnectCommands, line)
		}
	}
	certFP := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.FormValue("certfp")), ":", ""))
	if actor.Admin {
		net.SourceIP = r.FormValue("source_ip")
		net.TLSInsecure = r.FormValue("tls_insecure") == "on"
	}

	// Only send what changed: any "network update" makes the bouncer
	// reconnect to the server, so saving an untouched form must be a no-op.
	// For a new network, compare against the zero value instead.
	var args []string
	args = flagIfChanged(args, "addr", orig.Addr, net.Addr)
	args = flagIfChanged(args, "name", orig.Name, net.Name)
	args = flagIfChanged(args, "nick", orig.Nick, net.Nick)
	args = flagIfChanged(args, "username", orig.Username, net.Username)
	args = flagIfChanged(args, "realname", orig.Realname, net.Realname)
	args = flagIfChanged(args, "pass", orig.Pass, net.Pass)
	args = flagIfChanged(args, "certfp", certFPHex(orig.CertFP), certFP)
	if isNew || orig.AutoAway != net.AutoAway {
		args = append(args, flagArg("auto-away", strconv.FormatBool(net.AutoAway)))
	}
	if isNew || orig.Enabled != net.Enabled {
		args = append(args, flagArg("enabled", strconv.FormatBool(net.Enabled)))
	}
	if !slices.Equal(orig.ConnectCommands, net.ConnectCommands) {
		if len(net.ConnectCommands) == 0 {
			args = append(args, flagArg("connect-command", "")) // clears the list
		}
		for _, cmd := range net.ConnectCommands {
			args = append(args, flagArg("connect-command", cmd))
		}
	}
	if actor.Admin {
		args = flagIfChanged(args, "source-ip", orig.SourceIP, net.SourceIP)
		if orig.TLSInsecure != net.TLSInsecure {
			args = append(args, flagArg("tls-insecure", strconv.FormatBool(net.TLSInsecure)))
		}
	}

	if isNew {
		if err := h.runAs(ctx, target.Username, asAdmin, append([]string{"network", "create"}, args...)...); err != nil {
			h.renderNetwork(w, r, actor, net, target, err.Error())
			return
		}
	} else if len(args) > 0 {
		if err := h.runAs(ctx, target.Username, asAdmin, append([]string{"network", "update", oldName}, args...)...); err != nil {
			h.renderNetwork(w, r, actor, net, target, err.Error())
			return
		}
	}
	name := net.GetName()

	// Certificate first: importing one switches the mechanism to EXTERNAL,
	// so the mechanism chosen below has to be applied after it.
	certImported, certRemoved := false, false
	if r.FormValue("remove_client_cert") == "on" {
		if len(orig.SASL.External.CertBlob) > 0 {
			if err := h.runAs(ctx, target.Username, asAdmin, "certfp", "remove", "-network", name); err != nil {
				h.renderNetwork(w, r, actor, net, target, "client certificate: "+err.Error())
				return
			}
			certRemoved = true
		}
	} else if pemText := strings.TrimSpace(r.FormValue("client_cert_pem")); pemText != "" {
		if err := h.runAs(ctx, target.Username, asAdmin, "certfp", "import", "-network", name, "--", pemText); err != nil {
			h.renderNetwork(w, r, actor, net, target, "client certificate: "+err.Error())
			return
		}
		certImported = true
	}

	var saslArgs []string
	switch mech := r.FormValue("sasl_mechanism"); mech {
	case "PLAIN":
		saslUser := r.FormValue("sasl_username")
		if saslUser == "" {
			saslUser = orig.SASL.Plain.Username
		}
		saslPass := r.FormValue("sasl_password")
		if saslPass == "" {
			saslPass = orig.SASL.Plain.Password
		}
		if certImported || orig.SASL.Mechanism != "PLAIN" || saslUser != orig.SASL.Plain.Username || saslPass != orig.SASL.Plain.Password {
			if saslUser == "" || saslPass == "" {
				h.renderNetwork(w, r, actor, net, target, "SASL PLAIN needs both a username and a password")
				return
			}
			saslArgs = []string{"sasl", "set-plain", "-network", name, "--", saslUser, saslPass}
		}
	case "EXTERNAL":
		if !certImported && (orig.SASL.Mechanism != "EXTERNAL" || certRemoved) {
			saslArgs = []string{"sasl", "set-external", "-network", name}
		}
	case "":
		if orig.SASL.Mechanism != "" || certImported {
			saslArgs = []string{"sasl", "reset", "-network", name}
		}
	default:
		h.renderNetwork(w, r, actor, net, target, "unsupported SASL mechanism")
		return
	}
	if saslArgs != nil {
		if err := h.runAs(ctx, target.Username, asAdmin, saslArgs...); err != nil {
			h.renderNetwork(w, r, actor, net, target, "SASL: "+err.Error())
			return
		}
	}

	redirect := "/admin/"
	if asAdmin {
		redirect = "/admin/users/" + url.PathEscape(target.Username)
		if saved, err := h.networkByName(ctx, target.ID, name); err == nil && saved != nil {
			redirect = "/admin/networks/" + strconv.FormatInt(saved.ID, 10) + "?username=" + url.QueryEscape(target.Username)
		}
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// networkByName finds a user's network by its display name (Name, or Addr
// when unnamed), the way BouncerServ commands refer to networks.
func (h *Handler) networkByName(ctx context.Context, userID int64, name string) (*database.Network, error) {
	networks, err := h.DB.ListNetworks(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range networks {
		if networks[i].GetName() == name {
			return &networks[i], nil
		}
	}
	return nil, nil
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
	net, ok, err := h.findNetwork(r.Context(), target.ID, strconv.FormatInt(id, 10))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	asAdmin := target.Username != actor.Username
	if err := h.runAs(r.Context(), target.Username, asAdmin, "network", "delete", net.GetName()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirect := "/admin/"
	if asAdmin {
		redirect = "/admin/users/" + url.PathEscape(target.Username)
	}
	http.Redirect(w, r, redirect, http.StatusFound)
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

	ctx := r.Context()
	u := database.NewUser("")
	if existing {
		found, err := h.DB.GetUser(ctx, usernameParam)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		u = found
	} else {
		u.Username = r.FormValue("username")
	}
	orig := *u
	if !existing {
		// compare against what "user create" defaults to, not NewUser's
		// pre-filled values, so explicit choices are always sent
		orig = database.User{}
	}

	u.Nick = r.FormValue("nick")
	u.Realname = r.FormValue("realname")
	u.SourceIP = r.FormValue("source_ip")
	u.Admin = r.FormValue("admin") == "on"
	u.Enabled = r.FormValue("enabled") == "on"
	if mn, err := strconv.Atoi(r.FormValue("max_networks")); err == nil {
		u.MaxNetworks = mn
	}
	password := r.FormValue("password")
	fail := func(msg string) {
		h.render(w, r, "user.html", "User", actor, msg, map[string]any{"User": u, "Existing": existing})
	}

	self := existing && u.Username == actor.Username
	if self && (u.Admin != orig.Admin || u.Enabled != orig.Enabled) {
		fail("you can't change the admin or enabled flags of your own account")
		return
	}

	// Account-level flags, run from the admin's own context ("user create",
	// or "user update <name>" for someone else).
	var args []string
	if !self {
		if !existing || u.Admin != orig.Admin {
			args = append(args, flagArg("admin", strconv.FormatBool(u.Admin)))
		}
		if !existing || u.Enabled != orig.Enabled {
			args = append(args, flagArg("enabled", strconv.FormatBool(u.Enabled)))
		}
	}
	if u.MaxNetworks != orig.MaxNetworks {
		args = append(args, flagArg("max-networks", strconv.Itoa(u.MaxNetworks)))
	}
	args = flagIfChanged(args, "source-ip", orig.SourceIP, u.SourceIP)
	if password != "" {
		args = append(args, flagArg("password", password))
	}

	// Nick/realname can only be changed by the user themself, so for other
	// existing users they go through that user's own context instead
	// (like "user run <name> user update -nick ...").
	var identityArgs []string
	identityArgs = flagIfChanged(identityArgs, "nick", orig.Nick, u.Nick)
	identityArgs = flagIfChanged(identityArgs, "realname", orig.Realname, u.Realname)

	switch {
	case !existing:
		if password == "" {
			fail("password is required for new users")
			return
		}
		cmd := append([]string{"user", "create", flagArg("username", u.Username)}, args...)
		cmd = append(cmd, identityArgs...)
		if err := h.runAs(ctx, actor.Username, true, cmd...); err != nil {
			fail(err.Error())
			return
		}
	case self:
		args = append(args, identityArgs...)
		if len(args) > 0 {
			if err := h.runAs(ctx, actor.Username, true, append([]string{"user", "update"}, args...)...); err != nil {
				fail(err.Error())
				return
			}
		}
	default:
		if len(args) > 0 {
			if err := h.runAs(ctx, actor.Username, true, append([]string{"user", "update", u.Username}, args...)...); err != nil {
				fail(err.Error())
				return
			}
		}
		if len(identityArgs) > 0 {
			if err := h.runAs(ctx, u.Username, true, append([]string{"user", "update"}, identityArgs...)...); err != nil {
				fail(err.Error())
				return
			}
		}
	}
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (h *Handler) handleUserDelete(w http.ResponseWriter, r *http.Request, actor *database.User) {
	username := r.PathValue("username")
	if username == actor.Username {
		http.Error(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}
	if _, err := h.DB.GetUser(r.Context(), username); err != nil {
		http.NotFound(w, r)
		return
	}
	// "user delete" also stops the user's bouncer and closes their
	// connections, which a bare database delete wouldn't do.
	if err := h.runAs(r.Context(), actor.Username, true, "user", "delete", username, sake.UserDeleteToken(username)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

// --- channels (self-service; admins may edit other users' via ?username=) ---

var messageFilterNames = map[string]database.MessageFilter{
	"default":   database.FilterDefault,
	"none":      database.FilterNone,
	"highlight": database.FilterHighlight,
	"message":   database.FilterMessage,
}

// resolveNetworkForChannels loads the parent network (from the {netID} path
// segment) for a channel request, verifying it belongs to the resolved
// target user.
func (h *Handler) resolveNetworkForChannels(ctx context.Context, r *http.Request, actor *database.User) (target *database.User, net *database.Network, err error) {
	target, err = h.targetForRequest(r, actor)
	if err != nil {
		return nil, nil, err
	}
	net, ok, err := h.findNetwork(ctx, target.ID, r.PathValue("netID"))
	if err != nil {
		return nil, nil, err
	}
	if !ok || net.ID == 0 {
		return nil, nil, errNotFound
	}
	return target, net, nil
}

func (h *Handler) findChannel(ctx context.Context, networkID int64, idStr string) (ch *database.Channel, ok bool, err error) {
	if idStr == "" || idStr == "new" {
		return &database.Channel{}, true, nil
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return nil, false, nil
	}
	channels, err := h.DB.ListChannels(ctx, networkID)
	if err != nil {
		return nil, false, err
	}
	for i := range channels {
		if channels[i].ID == id {
			return &channels[i], true, nil
		}
	}
	return nil, false, nil
}

func (h *Handler) renderChannel(w http.ResponseWriter, r *http.Request, actor *database.User, ch *database.Channel, net *database.Network, targetUsername, errMsg string) {
	h.render(w, r, "channel.html", "Channel", actor, errMsg, map[string]any{
		"Channel":            ch,
		"NetworkID":          net.ID,
		"TargetUsername":     targetUsername,
		"DetachAfterMinutes": int64(ch.DetachAfter / time.Minute),
	})
}

func (h *Handler) handleChannelForm(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, net, err := h.resolveNetworkForChannels(r.Context(), r, actor)
	if err != nil {
		writeResolveError(w, r, err)
		return
	}

	ch, ok, err := h.findChannel(r.Context(), net.ID, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}

	h.renderChannel(w, r, actor, ch, net, target.Username, "")
}

func (h *Handler) handleChannelSave(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, net, err := h.resolveNetworkForChannels(r.Context(), r, actor)
	if err != nil {
		writeResolveError(w, r, err)
		return
	}

	ch, ok, err := h.findChannel(r.Context(), net.ID, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}

	isNew := ch.ID == 0
	if isNew {
		ch.Name = strings.TrimSpace(r.FormValue("name"))
	}
	ch.Key = r.FormValue("key")
	ch.Detached = r.FormValue("detached") == "on"

	// The select values are BouncerServ's own filter names; keep the parsed
	// copy in ch so a failed save re-renders with the user's choices.
	var args []string
	for _, f := range []struct {
		form, flag string
		dst        *database.MessageFilter
	}{
		{"relay_detached", "relay-detached", &ch.RelayDetached},
		{"reattach_on", "reattach-on", &ch.ReattachOn},
		{"detach_on", "detach-on", &ch.DetachOn},
	} {
		v := r.FormValue(f.form)
		filter, ok := messageFilterNames[v]
		if !ok {
			h.renderChannel(w, r, actor, ch, net, target.Username, "invalid value for "+f.flag)
			return
		}
		*f.dst = filter
		args = append(args, flagArg(f.flag, v))
	}

	minutes, err := strconv.ParseInt(r.FormValue("detach_after_minutes"), 10, 64)
	if err != nil || minutes < 0 {
		h.renderChannel(w, r, actor, ch, net, target.Username, "auto-detach-after must be a non-negative number of minutes")
		return
	}
	ch.DetachAfter = time.Duration(minutes) * time.Minute
	args = append(args, flagArg("detach-after", strconv.FormatInt(minutes, 10)+"m"), flagArg("key", ch.Key))

	// BouncerServ addresses channels as "<channel>/<network>" when the
	// command isn't sent from a network-bound connection.
	qualified := ch.Name + "/" + net.GetName()
	asAdmin := target.Username != actor.Username
	if isNew {
		if err := h.runAs(r.Context(), target.Username, asAdmin, append([]string{"channel", "create", qualified}, args...)...); err != nil {
			h.renderChannel(w, r, actor, ch, net, target.Username, err.Error())
			return
		}
		// "channel create" always joins: detaching is a separate step
		if ch.Detached {
			if err := h.runAs(r.Context(), target.Username, asAdmin, "channel", "update", qualified, flagArg("detached", "true")); err != nil {
				h.renderChannel(w, r, actor, ch, net, target.Username, err.Error())
				return
			}
		}
	} else {
		args = append(args, flagArg("detached", strconv.FormatBool(ch.Detached)))
		if err := h.runAs(r.Context(), target.Username, asAdmin, append([]string{"channel", "update", qualified}, args...)...); err != nil {
			h.renderChannel(w, r, actor, ch, net, target.Username, err.Error())
			return
		}
	}

	redirect := "/admin/networks/" + strconv.FormatInt(net.ID, 10)
	if target.Username != actor.Username {
		redirect += "?username=" + target.Username
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *Handler) handleChannelDelete(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, net, err := h.resolveNetworkForChannels(r.Context(), r, actor)
	if err != nil {
		writeResolveError(w, r, err)
		return
	}

	ch, ok, err := h.findChannel(r.Context(), net.ID, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || ch.ID == 0 {
		http.NotFound(w, r)
		return
	}

	asAdmin := target.Username != actor.Username
	if err := h.runAs(r.Context(), target.Username, asAdmin, "channel", "delete", ch.Name+"/"+net.GetName()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	redirect := "/admin/networks/" + strconv.FormatInt(net.ID, 10)
	if target.Username != actor.Username {
		redirect += "?username=" + target.Username
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// --- ignores (self-service; admins may edit other users' via ?username=) ---

func (h *Handler) handleIgnoreAdd(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, net, err := h.resolveNetworkForChannels(r.Context(), r, actor)
	if err != nil {
		writeResolveError(w, r, err)
		return
	}

	mask := strings.TrimSpace(r.FormValue("mask"))
	if mask == "" {
		h.renderNetwork(w, r, actor, net, target, "ignore mask can't be empty")
		return
	}
	asAdmin := target.Username != actor.Username
	if err := h.runAs(r.Context(), target.Username, asAdmin, "ignore", "add", "-network", net.GetName(), "--", mask); err != nil {
		h.renderNetwork(w, r, actor, net, target, "ignore: "+err.Error())
		return
	}
	http.Redirect(w, r, networkURL(net.ID, target, actor)+"#ignores", http.StatusFound)
}

func (h *Handler) handleIgnoreDelete(w http.ResponseWriter, r *http.Request, actor *database.User) {
	target, net, err := h.resolveNetworkForChannels(r.Context(), r, actor)
	if err != nil {
		writeResolveError(w, r, err)
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ignores, err := h.DB.ListIgnores(r.Context(), net.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	mask := ""
	for _, ig := range ignores {
		if ig.ID == id {
			mask = ig.Mask
			break
		}
	}
	if mask == "" {
		http.NotFound(w, r)
		return
	}

	asAdmin := target.Username != actor.Username
	if err := h.runAs(r.Context(), target.Username, asAdmin, "ignore", "delete", "-network", net.GetName(), "--", mask); err != nil {
		h.renderNetwork(w, r, actor, net, target, "ignore: "+err.Error())
		return
	}
	http.Redirect(w, r, networkURL(net.ID, target, actor)+"#ignores", http.StatusFound)
}

// networkURL is the network page's URL, carrying ?username= when an admin
// manages someone else's network.
func networkURL(netID int64, target, actor *database.User) string {
	u := "/admin/networks/" + strconv.FormatInt(netID, 10)
	if target.Username != actor.Username {
		u += "?username=" + url.QueryEscape(target.Username)
	}
	return u
}

// --- running BouncerServ commands ---

// commandTimeout bounds how long a webadmin request waits on the bouncer.
const commandTimeout = 15 * time.Second

// runAs runs a BouncerServ command in username's bouncer, so the change
// applies live and the running bouncer's state stays in sync with the
// database (see Server.RunCommand). asAdmin must only be true when an admin
// acts on another user's account, or for admin-only commands.
func (h *Handler) runAs(ctx context.Context, username string, asAdmin bool, args ...string) error {
	if h.Srv == nil {
		return errors.New("the bouncer is not available")
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	_, err := h.Srv.RunCommand(ctx, username, asAdmin, args)
	return err
}

// flagArg formats a BouncerServ flag as a single "-name=value" word, which
// both plain bool flags (fs.Bool, needing "=") and value flags accept, and
// which can't be confused with a following flag when value starts with "-".
func flagArg(name, value string) string {
	return "-" + name + "=" + value
}

// flagIfChanged appends -name=new to args when new differs from old.
func flagIfChanged(args []string, name, old, new string) []string {
	if old != new {
		args = append(args, flagArg(name, new))
	}
	return args
}

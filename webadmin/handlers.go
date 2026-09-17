package webadmin

import (
	"context"
	"embed"
	"encoding/hex"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TehPeGaSuS/sake/database"
)

//go:embed templates/*.html
var templateFS embed.FS

// Each page file defines a template named "body", so pages must be parsed
// as separate template sets (each paired with layout.html) rather than all
// together - otherwise the "body" definitions collide and only one survives.
var pages = map[string]*template.Template{}

var templateFuncs = template.FuncMap{
	// certFPHex strips the "sha-256:"/"sha-512:" storage prefix so the form
	// field round-trips as plain hex, matching what a user would paste in.
	"certFPHex": func(certFP string) string {
		if i := strings.IndexByte(certFP, ':'); i >= 0 {
			return certFP[i+1:]
		}
		return certFP
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
	h.render(w, r, "account.html", "My account", actor, errMsg, extra)
}

func (h *Handler) handleAccountForm(w http.ResponseWriter, r *http.Request, actor *database.User) {
	h.renderAccount(w, r, actor, "")
}

func (h *Handler) handleAccountSave(w http.ResponseWriter, r *http.Request, actor *database.User) {
	actor.Nick = r.FormValue("nick")
	actor.Realname = r.FormValue("realname")
	if actor.Admin {
		actor.SourceIP = r.FormValue("source_ip")
	}
	if pw := r.FormValue("password"); pw != "" {
		if err := actor.SetPassword(pw); err != nil {
			h.renderAccount(w, r, actor, err.Error())
			return
		}
	}

	if r.FormValue("remove_default_cert") == "on" {
		actor.SASLExternal.CertBlob = nil
		actor.SASLExternal.PrivKeyBlob = nil
	} else if pemText := r.FormValue("default_cert_pem"); pemText != "" {
		certDER, keyDER, err := parseClientCertPEM(pemText)
		if err != nil {
			h.renderAccount(w, r, actor, "default certificate: "+err.Error())
			return
		}
		actor.SASLExternal.CertBlob = certDER
		actor.SASLExternal.PrivKeyBlob = keyDER
	}

	if err := h.DB.StoreUser(r.Context(), actor); err != nil {
		h.renderAccount(w, r, actor, err.Error())
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

	if certFP := r.FormValue("certfp"); certFP != "" {
		normalized := strings.ToLower(strings.ReplaceAll(certFP, ":", ""))
		if _, err := hex.DecodeString(normalized); err != nil {
			h.renderNetwork(w, r, actor, net, target, "server certificate fingerprint must be hex-encoded")
			return
		}
		switch len(normalized) {
		case 64:
			net.CertFP = "sha-256:" + normalized
		case 128:
			net.CertFP = "sha-512:" + normalized
		default:
			h.renderNetwork(w, r, actor, net, target, "server certificate fingerprint must be a SHA-256 or SHA-512 hash")
			return
		}
	} else {
		net.CertFP = ""
	}

	// SASL EXTERNAL certificate: update it independently of the chosen
	// mechanism below, so a cert pasted here is preserved even if the
	// mechanism is temporarily switched away and back.
	if r.FormValue("remove_client_cert") == "on" {
		net.SASL.External.CertBlob = nil
		net.SASL.External.PrivKeyBlob = nil
	} else if clientCertPEM := r.FormValue("client_cert_pem"); clientCertPEM != "" {
		certDER, keyDER, err := parseClientCertPEM(clientCertPEM)
		if err != nil {
			h.renderNetwork(w, r, actor, net, target, "client certificate: "+err.Error())
			return
		}
		net.SASL.External.CertBlob = certDER
		net.SASL.External.PrivKeyBlob = keyDER
	}

	switch mech := r.FormValue("sasl_mechanism"); mech {
	case "PLAIN":
		if u := r.FormValue("sasl_username"); u != "" {
			net.SASL.Plain.Username = u
		}
		if p := r.FormValue("sasl_password"); p != "" {
			net.SASL.Plain.Password = p
		}
		net.SASL.Mechanism = "PLAIN"
	case "EXTERNAL":
		if net.SASL.External.CertBlob == nil && target.SASLExternal.CertBlob == nil {
			h.renderNetwork(w, r, actor, net, target, "SASL EXTERNAL requires either a certificate for this network or a default certificate set on the account")
			return
		}
		net.SASL.Mechanism = "EXTERNAL"
	case "":
		net.SASL.Mechanism = ""
	default:
		h.renderNetwork(w, r, actor, net, target, "unsupported SASL mechanism")
		return
	}

	if actor.Admin {
		net.SourceIP = r.FormValue("source_ip")
		net.TLSInsecure = r.FormValue("tls_insecure") == "on"
	}

	if err := h.DB.StoreNetwork(r.Context(), target.ID, net); err != nil {
		h.renderNetwork(w, r, actor, net, target, err.Error())
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

	if ch.ID == 0 {
		ch.Name = r.FormValue("name")
	}
	ch.Key = r.FormValue("key")
	ch.Detached = r.FormValue("detached") == "on"

	filter, ok := messageFilterNames[r.FormValue("relay_detached")]
	if !ok {
		h.renderChannel(w, r, actor, ch, net, target.Username, "invalid value for relay-while-detached")
		return
	}
	ch.RelayDetached = filter

	filter, ok = messageFilterNames[r.FormValue("reattach_on")]
	if !ok {
		h.renderChannel(w, r, actor, ch, net, target.Username, "invalid value for reattach-on")
		return
	}
	ch.ReattachOn = filter

	filter, ok = messageFilterNames[r.FormValue("detach_on")]
	if !ok {
		h.renderChannel(w, r, actor, ch, net, target.Username, "invalid value for auto-detach-on")
		return
	}
	ch.DetachOn = filter

	minutes, err := strconv.ParseInt(r.FormValue("detach_after_minutes"), 10, 64)
	if err != nil || minutes < 0 {
		h.renderChannel(w, r, actor, ch, net, target.Username, "auto-detach-after must be a non-negative number of minutes")
		return
	}
	ch.DetachAfter = time.Duration(minutes) * time.Minute

	if err := h.DB.StoreChannel(r.Context(), net.ID, ch); err != nil {
		h.renderChannel(w, r, actor, ch, net, target.Username, err.Error())
		return
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

	if err := h.DB.DeleteChannel(r.Context(), ch.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	redirect := "/admin/networks/" + strconv.FormatInt(net.ID, 10)
	if target.Username != actor.Username {
		redirect += "?username=" + target.Username
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

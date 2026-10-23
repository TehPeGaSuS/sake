package webadmin

import (
	"context"
	"time"

	sake "github.com/TehPeGaSuS/sake"
	"github.com/TehPeGaSuS/sake/database"
)

// statusTimeout bounds how long a page waits for a live status snapshot; a
// busy or stuck bouncer only costs the page its live columns.
const statusTimeout = 2 * time.Second

// liveStatus returns username's live state, or nil if it's unavailable (the
// user isn't running, or the bouncer didn't answer in time).
func (h *Handler) liveStatus(ctx context.Context, username string) *sake.UserStatus {
	if h.Srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	st, err := h.Srv.UserStatus(ctx, username)
	if err != nil {
		return nil
	}
	return st
}

// navData is the sidebar: the actor's own networks, with the channels of the
// network being viewed.
type navData struct {
	Section  string
	Networks []navNetwork
}

type navNetwork struct {
	ID       int64
	Name     string
	State    string
	Current  bool
	Channels []navChannel
}

type navChannel struct {
	ID        int64
	NetworkID int64
	Name      string
	State     string
	Current   bool
}

// buildNav reads the actor's networks for the sidebar. data carries the
// page's "Section", and "NavNetworkID"/"NavChannelID" when the page shows
// one of the actor's own networks or channels.
func (h *Handler) buildNav(ctx context.Context, actor *database.User, data map[string]any) navData {
	nav := navData{}
	nav.Section, _ = data["Section"].(string)
	curNet, _ := data["NavNetworkID"].(int64)
	curChan, _ := data["NavChannelID"].(int64)

	networks, err := h.DB.ListNetworks(ctx, actor.ID)
	if err != nil {
		return nav
	}
	live, ok := data["ActorLive"].(*sake.UserStatus)
	if !ok {
		live = h.liveStatus(ctx, actor.Username)
	}
	for i := range networks {
		net := &networks[i]
		item := navNetwork{
			ID:      net.ID,
			Name:    net.GetName(),
			State:   netState(live, net),
			Current: net.ID == curNet && curChan == 0,
		}
		if net.ID == curNet {
			channels, err := h.DB.ListChannels(ctx, net.ID)
			if err == nil {
				ns := netLive(live, net.ID)
				for j := range channels {
					ch := &channels[j]
					item.Channels = append(item.Channels, navChannel{
						ID:        ch.ID,
						NetworkID: net.ID,
						Name:      ch.Name,
						State:     chanState(ns, ch),
						Current:   ch.ID == curChan,
					})
				}
			}
		}
		nav.Networks = append(nav.Networks, item)
	}
	return nav
}

// netLive returns the live state of network id, or nil.
func netLive(st *sake.UserStatus, id int64) *sake.NetworkStatus {
	if st == nil {
		return nil
	}
	return st.Networks[id]
}

// chanLive returns the live state of channel id, or nil.
func chanLive(ns *sake.NetworkStatus, id int64) *sake.ChannelStatus {
	if ns == nil {
		return nil
	}
	return ns.Channels[id]
}

// netState is the status shown for a network: "connected", "disconnected",
// "disabled", or "unknown" when there's no live state.
func netState(st *sake.UserStatus, net *database.Network) string {
	if ns := netLive(st, net.ID); ns != nil {
		return ns.State
	}
	if !net.Enabled {
		return "disabled"
	}
	return "unknown"
}

// chanState is the status shown for a channel: "detached", "joined",
// "parted" (saved but not currently joined) or "unknown".
func chanState(ns *sake.NetworkStatus, ch *database.Channel) string {
	if ch.Detached {
		return "detached"
	}
	if ns == nil {
		return "unknown"
	}
	if cs := ns.Channels[ch.ID]; cs != nil && cs.Joined {
		return "joined"
	}
	return "parted"
}

// joined counts the joined channels of a network.
func joined(ns *sake.NetworkStatus) int {
	n := 0
	for _, cs := range ns.Channels {
		if cs.Joined {
			n++
		}
	}
	return n
}

var stateLabels = map[string]string{
	"connected":    "Connected",
	"running":      "Running",
	"disconnected": "Disconnected",
	"disabled":     "Disabled",
	"unknown":      "Not running",
	"joined":       "Joined",
	"detached":     "Detached",
	"parted":       "Not joined",
}

func stateLabel(state string) string {
	if l, ok := stateLabels[state]; ok {
		return l
	}
	return state
}

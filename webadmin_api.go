package soju

// sake: entry points used by the webadmin package. Every change the webadmin
// makes goes through a BouncerServ command run inside the target user's
// goroutine (the same path as "sakectl user run"), so the running bouncer's
// in-memory state and the database never diverge, and changes apply live.

import (
	"context"
	"crypto/sha1"
	"fmt"

	"github.com/TehPeGaSuS/sake/database"
)

// RunCommand runs the BouncerServ command params (already split into words)
// on behalf of username, inside that user's goroutine, and returns the lines
// the command printed. If asAdmin is false, the command runs with the user's
// own privileges, exactly as if they had sent it to BouncerServ themselves;
// if true, it runs with admin privileges, like "user run" does.
//
// Safe to call from any goroutine.
func (s *Server) RunCommand(ctx context.Context, username string, asAdmin bool, params []string) ([]string, error) {
	if len(params) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	u := s.getUser(username)
	if u == nil {
		return nil, fmt.Errorf("unknown username %q", username)
	}

	msgCh := make(chan userRunMsg, 1)
	ev := eventUserRun{
		params: params,
		ch:     msgCh,
		asUser: !asAdmin,
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case u.events <- ev:
	}

	var lines []string
	for {
		select {
		case <-ctx.Done():
			// Same caveat as handleUserRun: if the user goroutine stops
			// before handling the event, we'd otherwise block forever.
			return lines, fmt.Errorf("timeout executing command")
		case msg := <-msgCh:
			if msg.message != "" {
				lines = append(lines, msg.message)
			} else {
				return lines, msg.err
			}
		}
	}
}

// UserDeleteToken returns the confirmation token "user delete" expects for
// username. Keep in sync with handleUserDelete.
func UserDeleteToken(username string) string {
	hashBytes := sha1.Sum([]byte(username))
	return fmt.Sprintf("%x", hashBytes[0:3])
}

// UserStatus is a snapshot of a running user's live state.
type UserStatus struct {
	Clients  int // registered downstream connections, bound or not
	Networks map[int64]*NetworkStatus
}

// NetworkStatus is the live state of one network (see UserStatus).
type NetworkStatus struct {
	State     string // "connected", "disconnected" or "disabled"
	Nick      string
	Server    string // the upstream's own server name, once registered
	Account   string
	Away      bool
	LastError string
	Clients   int // downstream connections bound to this network
	Channels  map[int64]*ChannelStatus
}

// ChannelStatus is the live state of one saved channel (see NetworkStatus).
type ChannelStatus struct {
	Joined  bool
	Topic   string
	Modes   string
	Members int
}

// UserStatus returns a snapshot of username's live networks and channels,
// keyed by their database IDs. It returns (nil, nil) if the user isn't
// running. Safe to call from any goroutine.
func (s *Server) UserStatus(ctx context.Context, username string) (*UserStatus, error) {
	u := s.getUser(username)
	if u == nil {
		return nil, nil
	}

	var status UserStatus
	done := make(chan struct{})
	ev := eventInspect{
		done: done,
		f: func(u *user) {
			status.Networks = make(map[int64]*NetworkStatus, len(u.networks))
			for _, net := range u.networks {
				ns := &NetworkStatus{Channels: make(map[int64]*ChannelStatus)}
				uc := net.conn
				switch {
				case uc != nil:
					ns.State = "connected"
					ns.Nick = uc.nick
					ns.Server = uc.serverName
					ns.Account = uc.account
					ns.Away = uc.away
				case !net.Enabled:
					ns.State = "disabled"
				default:
					ns.State = "disconnected"
					if net.lastError != nil {
						ns.LastError = net.lastError.Error()
					}
				}
				net.channels.ForEach(func(_ string, ch *database.Channel) {
					cs := &ChannelStatus{}
					if uc != nil {
						if uch := uc.channels.Get(ch.Name); uch != nil {
							cs.Joined = true
							cs.Topic = uch.Topic
							cs.Members = uch.Members.Len()
							if uch.modes != nil {
								cs.Modes, _ = uch.modes.Format()
							}
						}
					}
					ns.Channels[ch.ID] = cs
				})
				status.Networks[net.ID] = ns
			}
			for _, dc := range u.downstreamConns {
				if !dc.registered {
					continue
				}
				status.Clients++
				if dc.network != nil {
					if ns := status.Networks[dc.network.ID]; ns != nil {
						ns.Clients++
					}
				}
			}
		},
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case u.events <- ev:
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return &status, nil
	}
}

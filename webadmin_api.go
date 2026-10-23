package soju

// sake: entry points used by the webadmin package. Every change the webadmin
// makes goes through a BouncerServ command run inside the target user's
// goroutine (the same path as "sakectl user run"), so the running bouncer's
// in-memory state and the database never diverge, and changes apply live.

import (
	"context"
	"crypto/sha1"
	"fmt"
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

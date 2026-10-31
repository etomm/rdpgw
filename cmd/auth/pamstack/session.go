package pamstack

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/msteinert/pam/v2"
)

// Session is the subset of a PAM transaction the auth service drives. The
// type lives here because the transaction, the generated stack and the
// session_manager.sh state are one concern.
type Session interface {
	Authenticate(pam.Flags) error
	AcctMgmt(pam.Flags) error
	PutEnv(string) error
	End() error
}

// startSession is swappable in tests to observe the PAM environment.
var startSession = func(service, user string, conv func(pam.Style, string) (string, error)) (Session, error) {
	return pam.StartFunc(service, user, conv)
}

// StartSession opens a PAM transaction for user and injects a fresh
// RDPGW_SESSION_ID into the PAM environment. The id keys the
// session_manager.sh state, so every authentication attempt gets its own; a
// transaction that cannot carry it is closed and returned as an error so the
// caller fails closed. The generated id is returned for logging/correlation.
func StartSession(service, user string, conv func(pam.Style, string) (string, error)) (Session, string, error) {
	sessionID := uuid.NewString()

	session, err := startSession(service, user, conv)
	if err != nil {
		return nil, sessionID, err
	}
	if err := session.PutEnv("RDPGW_SESSION_ID=" + sessionID); err != nil {
		_ = session.End()
		return nil, sessionID, fmt.Errorf("cannot set the PAM session id: %w", err)
	}
	return session, sessionID, nil
}

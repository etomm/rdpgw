package service

import (
	"context"
	"errors"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/pamstack"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/msteinert/pam/v2"
)

type fakePamSession struct {
	authCalls int
	acctCalls int
	endCalls  int
}

func (f *fakePamSession) Authenticate(pam.Flags) error { f.authCalls++; return nil }
func (f *fakePamSession) AcctMgmt(pam.Flags) error     { f.acctCalls++; return nil }
func (f *fakePamSession) PutEnv(string) error          { return nil }
func (f *fakePamSession) End() error                   { f.endCalls++; return nil }

// withFakePam makes every openSession call return a fresh fake and records
// the service/user it was called with.
func withFakePam(t *testing.T) (*[]*fakePamSession, *[]string) {
	t.Helper()
	prev := openSession
	var sessions []*fakePamSession
	var calls []string
	openSession = func(service, user string, _ func(pam.Style, string) (string, error)) (pamstack.Session, string, error) {
		f := &fakePamSession{}
		sessions = append(sessions, f)
		calls = append(calls, service+"|"+user)
		return f, "generated-session-id", nil
	}
	t.Cleanup(func() { openSession = prev })
	return &sessions, &calls
}

func TestAuthenticateUsesPAMSession(t *testing.T) {
	sessions, calls := withFakePam(t)
	s := New("rdpgw", config.Configuration{})

	r, err := s.Authenticate(context.Background(), &auth.UserPass{
		Username: "alice",
		Password: "s3cret",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !r.Authenticated {
		t.Fatal("Authenticate did not mark the response authenticated")
	}
	if len(*sessions) != 1 {
		t.Fatalf("PAM sessions = %d, want 1", len(*sessions))
	}
	f := (*sessions)[0]
	if f.authCalls != 1 || f.acctCalls != 1 || f.endCalls != 1 {
		t.Errorf("PAM calls auth/acct/end = %d/%d/%d, want 1/1/1", f.authCalls, f.acctCalls, f.endCalls)
	}
	if len(*calls) != 1 || (*calls)[0] != "rdpgw|alice" {
		t.Errorf("openSession calls = %v, want rdpgw|alice", *calls)
	}
}

// endFailSession simulates a PAM stack whose pam_end fails after a
// successful authentication. That must be logged, not fatal to the daemon.
type endFailSession struct {
	fakePamSession
}

func (f *endFailSession) End() error {
	f.endCalls++
	return errors.New("pam_end failed")
}

func TestAuthenticateSurvivesPamEndFailure(t *testing.T) {
	prev := openSession
	session := &endFailSession{}
	openSession = func(_, _ string, _ func(pam.Style, string) (string, error)) (pamstack.Session, string, error) {
		return session, "generated-session-id", nil
	}
	t.Cleanup(func() { openSession = prev })

	s := New("rdpgw", config.Configuration{})
	r, err := s.Authenticate(context.Background(), &auth.UserPass{
		Username: "alice",
		Password: "s3cret",
	})
	if err != nil {
		t.Fatalf("a failed pam_end must not fail the authentication: %v", err)
	}
	if !r.Authenticated {
		t.Error("response must stay authenticated")
	}
	if session.endCalls != 1 {
		t.Errorf("End calls = %d, want 1", session.endCalls)
	}
}

func TestAuthenticateStopsWhenSessionFails(t *testing.T) {
	prev := openSession
	openSession = func(_, _ string, _ func(pam.Style, string) (string, error)) (pamstack.Session, string, error) {
		return nil, "generated-session-id", errors.New("pam_start failed")
	}
	t.Cleanup(func() { openSession = prev })

	s := New("rdpgw", config.Configuration{})
	r, err := s.Authenticate(context.Background(), &auth.UserPass{
		Username: "alice",
		Password: "s3cret",
	})
	if err == nil {
		t.Fatal("Authenticate must fail when the PAM session cannot be opened")
	}
	if r.Authenticated {
		t.Error("response must not be authenticated")
	}
}

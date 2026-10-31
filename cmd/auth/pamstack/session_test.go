package pamstack

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/msteinert/pam/v2"
)

type fakeTransaction struct {
	env       []string
	putEnvErr error
	endCalls  int
}

func (f *fakeTransaction) Authenticate(pam.Flags) error { return nil }
func (f *fakeTransaction) AcctMgmt(pam.Flags) error     { return nil }
func (f *fakeTransaction) PutEnv(nameval string) error {
	f.env = append(f.env, nameval)
	return f.putEnvErr
}
func (f *fakeTransaction) End() error { f.endCalls++; return nil }

func withFakeTransaction(t *testing.T) (*fakeTransaction, *string) {
	t.Helper()
	prev := startSession
	f := &fakeTransaction{}
	var call string
	startSession = func(service, user string, _ func(pam.Style, string) (string, error)) (Session, error) {
		call = service + "|" + user
		return f, nil
	}
	t.Cleanup(func() { startSession = prev })
	return f, &call
}

func TestStartSessionInjectsSessionID(t *testing.T) {
	f, call := withFakeTransaction(t)

	session, id, err := StartSession("rdpgw", "alice", nil)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if session != f {
		t.Error("StartSession did not return the PAM transaction")
	}
	if *call != "rdpgw|alice" {
		t.Errorf("PAM started for %q, want rdpgw|alice", *call)
	}
	if _, err := uuid.Parse(id); err != nil {
		t.Errorf("session id %q is not a GUID: %v", id, err)
	}
	if len(f.env) != 1 || f.env[0] != "RDPGW_SESSION_ID="+id {
		t.Errorf("PAM env = %v, want exactly RDPGW_SESSION_ID=%s", f.env, id)
	}
}

func TestStartSessionFailsWhenPutEnvFails(t *testing.T) {
	f, _ := withFakeTransaction(t)
	f.putEnvErr = errors.New("pam_putenv failed")

	session, id, err := StartSession("rdpgw", "alice", nil)
	if err == nil {
		t.Fatal("StartSession must fail when RDPGW_SESSION_ID cannot be set")
	}
	if session != nil {
		t.Error("StartSession must not return a transaction after a setup failure")
	}
	if _, parseErr := uuid.Parse(id); parseErr != nil {
		t.Errorf("session id %q is not a GUID: %v", id, parseErr)
	}
	if f.endCalls != 1 {
		t.Errorf("PAM end calls = %d, want 1", f.endCalls)
	}
}

func TestStartSessionIDsAreUnique(t *testing.T) {
	prev := startSession
	startSession = func(_, _ string, _ func(pam.Style, string) (string, error)) (Session, error) {
		return &fakeTransaction{}, nil
	}
	t.Cleanup(func() { startSession = prev })

	_, first, err := StartSession("rdpgw", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := StartSession("rdpgw", "alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("both attempts used the same session id: %q", first)
	}
}

func TestStartSessionReturnsStartError(t *testing.T) {
	prev := startSession
	startSession = func(_, _ string, _ func(pam.Style, string) (string, error)) (Session, error) {
		return nil, errors.New("pam_start failed")
	}
	t.Cleanup(func() { startSession = prev })

	session, id, err := StartSession("rdpgw", "alice", nil)
	if err == nil {
		t.Fatal("StartSession must return the pam_start error")
	}
	if session != nil {
		t.Error("no transaction should be returned on pam_start failure")
	}
	if _, parseErr := uuid.Parse(id); parseErr != nil {
		t.Errorf("session id %q is not a GUID: %v", id, parseErr)
	}
}

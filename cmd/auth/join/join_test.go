package join

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

// testJoiner builds a joiner with millisecond-scale timings so the retry and
// wait loops stay fast in tests.
func testJoiner(autoJoin bool) *Joiner {
	j := New(config.Configuration{Winbind: &config.WinbindConfig{
		Domain:    "corp.example.com",
		Workgroup: "CORP",
		AutoJoin:  autoJoin,
	}})
	j.timeout = 100 * time.Millisecond
	j.poll = 5 * time.Millisecond
	j.backoffInitial = time.Millisecond
	j.backoffMax = 4 * time.Millisecond
	j.env = func(string) string { return "" }
	return j
}

func withCredentials(j *Joiner) {
	j.env = func(key string) string {
		switch key {
		case adJoinUserEnv:
			return "svc-join"
		case adJoinPasswordEnv:
			return "s3cret"
		}
		return ""
	}
}

func TestJoinerDefaultTimeout(t *testing.T) {
	j := New(config.Configuration{})
	if want := 10 * time.Minute; j.timeout != want {
		t.Errorf("default timeout = %s, want %s", j.timeout, want)
	}

	j = New(config.Configuration{Winbind: &config.WinbindConfig{JoinTimeout: 3}})
	if want := 3 * time.Minute; j.timeout != want {
		t.Errorf("configured timeout = %s, want %s", j.timeout, want)
	}
}

func TestJoinerAlreadyJoinedSkipsJoin(t *testing.T) {
	j := testJoiner(true)
	var commands []string
	j.run = func(_ context.Context, name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}

	if err := j.EnsureJoined(context.Background()); err != nil {
		t.Fatalf("EnsureJoined: %v", err)
	}
	if len(commands) != 1 || commands[0] != "net ads testjoin" {
		t.Errorf("commands = %v, want only the testjoin pre-check", commands)
	}
}

func TestJoinerManualWaitDetectsJoin(t *testing.T) {
	j := testJoiner(false)
	var testjoins int32
	j.run = func(_ context.Context, name string, args ...string) error {
		if name != "net" || len(args) < 2 || args[1] != "testjoin" {
			t.Errorf("unexpected command during manual wait: %s %v", name, args)
			return nil
		}
		if atomic.AddInt32(&testjoins, 1) >= 3 {
			return nil
		}
		return errors.New("not joined")
	}

	if err := j.EnsureJoined(context.Background()); err != nil {
		t.Fatalf("EnsureJoined: %v", err)
	}
	if got := atomic.LoadInt32(&testjoins); got < 3 {
		t.Errorf("testjoin calls = %d, want at least 3", got)
	}
}

func TestJoinerManualWaitTimesOut(t *testing.T) {
	j := testJoiner(false)
	j.run = func(context.Context, string, ...string) error { return errors.New("not joined") }

	err := j.EnsureJoined(context.Background())
	if !errors.Is(err, ErrJoinUnavailable) {
		t.Fatalf("EnsureJoined = %v, want ErrJoinUnavailable", err)
	}
	for _, want := range []string{"timed out waiting for the manual domain join", "net ads join -U Administrator", adJoinUserEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestJoinerAutoJoinMissingCredentials(t *testing.T) {
	j := testJoiner(true)
	var joinCalls int32
	j.run = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 1 && args[1] == "join" {
			atomic.AddInt32(&joinCalls, 1)
		}
		return errors.New("not joined")
	}

	err := j.EnsureJoined(context.Background())
	if !errors.Is(err, ErrJoinUnavailable) {
		t.Fatalf("EnsureJoined = %v, want ErrJoinUnavailable", err)
	}
	if !strings.Contains(err.Error(), adJoinUserEnv+"/"+adJoinPasswordEnv+" are not set") {
		t.Errorf("error does not explain the missing credentials: %v", err)
	}
	if got := atomic.LoadInt32(&joinCalls); got != 0 {
		t.Errorf("join attempts = %d, want 0 without credentials", got)
	}
}

func TestJoinerAutoJoinRetriesThenSucceeds(t *testing.T) {
	j := testJoiner(true)
	withCredentials(j)

	var joined bool
	var joinAttempts int32
	j.run = func(_ context.Context, name string, args ...string) error {
		if name != "net" || len(args) < 2 {
			return errors.New("unexpected command")
		}
		switch args[1] {
		case "testjoin":
			if joined {
				return nil
			}
			return errors.New("not joined")
		case "join":
			attempt := atomic.AddInt32(&joinAttempts, 1)
			if attempt < 3 {
				return errors.New("dc busy")
			}
			joined = true
			return nil
		default:
			return errors.New("unexpected net subcommand")
		}
	}

	if err := j.EnsureJoined(context.Background()); err != nil {
		t.Fatalf("EnsureJoined: %v", err)
	}
	if got := atomic.LoadInt32(&joinAttempts); got != 3 {
		t.Errorf("join attempts = %d, want 3", got)
	}
}

func TestJoinerAutoJoinSendsCredentials(t *testing.T) {
	j := testJoiner(true)
	withCredentials(j)

	var joinArgs []string
	j.run = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 1 && args[1] == "join" {
			joinArgs = append([]string(nil), args...)
			return nil
		}
		if len(args) > 1 && args[1] == "testjoin" {
			if joinArgs != nil {
				return nil
			}
			return errors.New("not joined")
		}
		return errors.New("unexpected command")
	}

	if err := j.EnsureJoined(context.Background()); err != nil {
		t.Fatalf("EnsureJoined: %v", err)
	}
	if len(joinArgs) == 0 {
		t.Fatal("net ads join was never executed")
	}
	got := strings.Join(joinArgs, " ")
	if !strings.Contains(got, "-U svc-join%s3cret") {
		t.Errorf("join command %q does not carry AD_JOIN_USER%%AD_JOIN_PASSWORD", got)
	}
}

func TestJoinerAutoJoinTimesOut(t *testing.T) {
	j := testJoiner(true)
	withCredentials(j)
	var joinAttempts int32
	j.run = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 1 && args[1] == "join" {
			atomic.AddInt32(&joinAttempts, 1)
		}
		return errors.New("domain unreachable")
	}

	err := j.EnsureJoined(context.Background())
	if !errors.Is(err, ErrJoinUnavailable) {
		t.Fatalf("EnsureJoined = %v, want ErrJoinUnavailable", err)
	}
	if !strings.Contains(err.Error(), "could not join the domain after") {
		t.Errorf("error does not report the retry exhaustion: %v", err)
	}
	if got := atomic.LoadInt32(&joinAttempts); got < 2 {
		t.Errorf("join attempts = %d, want repeated retries with backoff", got)
	}
}

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewWinbinddSupervisorDefaults(t *testing.T) {
	t.Setenv(winbinddPathEnv, "")
	t.Setenv(winbinddDebugEnv, "")
	s := New()
	if s.path != defaultWinbinddPath {
		t.Errorf("path = %q, want %q", s.path, defaultWinbinddPath)
	}
	want := "-F --no-process-group --debug-stdout -d 2"
	if got := strings.Join(s.args, " "); got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

func TestNewWinbinddSupervisorEnvOverrides(t *testing.T) {
	t.Setenv(winbinddPathEnv, "/usr/sbin/winbindd")
	t.Setenv(winbinddDebugEnv, "5")
	s := New()
	if s.path != "/usr/sbin/winbindd" {
		t.Errorf("path = %q, want /usr/sbin/winbindd", s.path)
	}
	want := "-F --no-process-group --debug-stdout -d 5"
	if got := strings.Join(s.args, " "); got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

func TestNewWinbinddSupervisorInvalidDebugFallsBack(t *testing.T) {
	t.Setenv(winbinddDebugEnv, "loud")
	s := New()
	want := "-F --no-process-group --debug-stdout -d 2"
	if got := strings.Join(s.args, " "); got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

func TestExternalWinbindEnv(t *testing.T) {
	t.Setenv(externalWinbindEnv, "")
	if External() {
		t.Error("external mode must be off by default")
	}
	t.Setenv(externalWinbindEnv, "1")
	if !External() {
		t.Error("external mode must be on with " + externalWinbindEnv + "=1")
	}
}

func TestSupervisorMirrorsOutputAndStops(t *testing.T) {
	logs := captureLog(t)

	s := &Supervisor{
		path:      "sh",
		args:      []string{"-c", "echo child-line; echo child-err >&2; exec sleep 30"},
		probe:     func(context.Context) error { return nil },
		stopGrace: 5 * time.Second,
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = s.Stop() }()

	waitFor(t, func() bool {
		out := logs.String()
		return strings.Contains(out, "[winbindd] child-line") &&
			strings.Contains(out, "[winbindd] child-err")
	}, "child stdout/stderr mirrored with the [winbindd] prefix")

	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("child did not exit after Stop")
	}
}

func TestSupervisorStartMissingBinary(t *testing.T) {
	s := &Supervisor{path: t.TempDir() + "/does-not-exist", probe: func(context.Context) error { return nil }}
	if err := s.Start(); err == nil {
		_ = s.Stop()
		t.Fatal("starting a missing binary must fail")
	}
}

func TestWaitReadyPollsUntilProbeSucceeds(t *testing.T) {
	var calls int32
	s := &Supervisor{
		probe: func(context.Context) error {
			if atomic.AddInt32(&calls, 1) < 3 {
				return errors.New("not ready")
			}
			return nil
		},
		readyInitial: time.Millisecond,
		readyMax:     2 * time.Millisecond,
	}
	if err := s.WaitReady(context.Background()); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("probe calls = %d, want 3", got)
	}
}

func TestWaitReadyFailsWhenChildExits(t *testing.T) {
	s := &Supervisor{
		path:         "sh",
		args:         []string{"-c", "exit 3"},
		probe:        func(context.Context) error { return errors.New("not ready") },
		readyInitial: time.Millisecond,
		readyMax:     time.Millisecond,
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	err := s.WaitReady(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exited before becoming ready") {
		t.Fatalf("WaitReady = %v, want an exited-before-ready error", err)
	}
}

func TestWaitReadyHonoursContext(t *testing.T) {
	s := &Supervisor{
		probe:        func(context.Context) error { return errors.New("not ready") },
		readyInitial: 5 * time.Millisecond,
		readyMax:     5 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady = %v, want context deadline exceeded", err)
	}
}

func TestStopKillsChildAfterGracePeriod(t *testing.T) {
	logs := captureLog(t)
	s := &Supervisor{
		path: "sh",
		// Ignore SIGTERM so only the kill path can end the process. The
		// marker line synchronizes: without it Stop can race the child's
		// trap installation and the child dies on SIGTERM.
		args:      []string{"-c", `trap "" TERM; echo trap-installed; while true; do sleep 0.2; done`},
		probe:     func(context.Context) error { return nil },
		stopGrace: 100 * time.Millisecond,
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitFor(t, func() bool {
		return strings.Contains(logs.String(), "[winbindd] trap-installed")
	}, "child to install its SIGTERM trap")
	start := time.Now()
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed < s.stopGrace {
		t.Errorf("Stop returned after %s, before the grace period %s (SIGTERM must have failed silently)", elapsed, s.stopGrace)
	}
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("child did not exit after the kill")
	}
}

// captureLog redirects the standard logger into a buffer for the duration of
// the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

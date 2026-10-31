// Package supervisor owns the winbindd child process: it starts it with
// the operator-configured binary and debug level, mirrors its output into
// the Go logger and terminates it gracefully on shutdown. It also re-execs
// and supervises the unprivileged gRPC server when rdpgw-auth drops
// privileges with --serve-user.
package supervisor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// winbinddOutputPrefix tags every line the child writes to stdout or
	// stderr so the daemon's own logs stay distinguishable.
	winbinddOutputPrefix = "[winbindd]"
	// winbinddProbeBinary asks winbindd whether it accepts requests.
	winbinddProbeBinary = "wbinfo"

	winbinddReadyInitial = 500 * time.Millisecond
	winbinddReadyMax     = 2 * time.Second
	winbinddStopGrace    = 10 * time.Second

	// externalWinbindEnv keeps the legacy container switch working: when
	// set to "1" the host provides winbindd and rdpgw-auth must not spawn
	// its own child.
	externalWinbindEnv = "RDPGW_AUTH_EXTERNAL_WINBIND"

	// ExternalReadyTimeout bounds how long the daemon waits for a
	// host-provided winbindd before giving up.
	ExternalReadyTimeout = 30 * time.Second

	// Supervisor knobs are environment driven: they are deployment
	// concerns, not part of the rdpgw-auth configuration schema.
	winbinddPathEnv      = "RDPGW_WINBIND_PATH"
	winbinddDebugEnv     = "RDPGW_WINBIND_DEBUG"
	defaultWinbinddPath  = "winbindd"
	defaultWinbinddDebug = 2
)

// External reports whether the deployment uses a winbindd that runs
// outside this container (host mount compatibility mode).
func External() bool {
	return os.Getenv(externalWinbindEnv) == "1"
}

// probeWinbindd is the readiness check: wbinfo -p exits 0 only when the
// winbindd child answers. Replaced in tests.
var probeWinbindd = func(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, winbinddProbeBinary, "-p").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wbinfo -p: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Supervisor owns the winbindd child process.
type Supervisor struct {
	path string
	args []string

	// probe reports whether winbindd is ready to answer requests.
	probe func(context.Context) error
	// readyInitial/readyMax bound the readiness poll backoff.
	readyInitial time.Duration
	readyMax     time.Duration
	// stopGrace bounds how long Stop waits after SIGTERM before killing.
	stopGrace time.Duration

	cmd  *exec.Cmd
	done chan struct{}
	err  error
	wg   sync.WaitGroup
}

// New builds a supervisor for the configured winbindd binary. The command
// line mirrors the legacy wrapper's
// `winbindd -F --no-process-group --debug-stdout -d 2`. RDPGW_WINBIND_PATH
// and RDPGW_WINBIND_DEBUG let an operator point at another binary or raise
// the debug level (e.g. -d 5) without rebuilding the image.
func New() *Supervisor {
	path := strings.TrimSpace(os.Getenv(winbinddPathEnv))
	if path == "" {
		path = defaultWinbinddPath
	}
	debug := defaultWinbinddDebug
	if raw := strings.TrimSpace(os.Getenv(winbinddDebugEnv)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			debug = n
		} else {
			log.Printf("Supervisor: ignoring invalid %s=%q, using -d %d",
				winbinddDebugEnv, raw, debug)
		}
	}
	return &Supervisor{
		path: path,
		args: []string{
			"-F",                 // foreground: the child dies with the daemon
			"--no-process-group", // the child must not change its process group
			"--debug-stdout",     // logs go to stdout, which we pipe into ours
			"-d", strconv.Itoa(debug),
		},
		probe:        probeWinbindd,
		readyInitial: winbinddReadyInitial,
		readyMax:     winbinddReadyMax,
		stopGrace:    winbinddStopGrace,
	}
}

// Start launches the configured child and starts the output pumps.
func (s *Supervisor) Start() error {
	cmd := exec.Command(s.path, s.args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("supervisor: cannot pipe %s stdout: %w", s.path, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("supervisor: cannot pipe %s stderr: %w", s.path, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("supervisor: cannot start %s (%s): %w",
			s.path, strings.Join(s.args, " "), err)
	}
	s.cmd = cmd
	s.done = make(chan struct{})

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		mirrorOutput(stdout, winbinddOutputPrefix)
	}()
	go func() {
		defer s.wg.Done()
		mirrorOutput(stderr, winbinddOutputPrefix)
	}()

	go func() {
		// The pipe readers end at EOF when the child exits, so collect
		// them before Wait (Wait closes the pipes).
		s.wg.Wait()
		s.err = cmd.Wait()
		close(s.done)
	}()

	log.Printf("Supervisor: started %s %s (pid %d)",
		s.path, strings.Join(s.args, " "), cmd.Process.Pid)
	return nil
}

// mirrorOutput forwards one child stream line by line into the Go logger.
func mirrorOutput(r io.Reader, prefix string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		log.Printf("%s %s", prefix, scanner.Text())
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Printf("%s output stream error: %v", prefix, err)
	}
}

// WaitReady polls wbinfo -p until winbindd answers, the child dies or the
// context is cancelled. It must succeed before the gRPC socket is opened:
// serving logins while winbindd is still starting turns every NTLM/PAM
// attempt into an avoidable failure.
func (s *Supervisor) WaitReady(ctx context.Context) error {
	first, max := s.readyInitial, s.readyMax
	if first <= 0 {
		first = winbinddReadyInitial
	}
	if max < first {
		max = winbinddReadyMax
	}
	delay := first
	for {
		err := s.probe(ctx)
		if err == nil {
			log.Printf("Supervisor: winbindd is ready")
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("supervisor: waiting for winbindd: %w", ctx.Err())
		case <-s.done:
			if s.err != nil {
				return fmt.Errorf("supervisor: winbindd exited before becoming ready: %w", s.err)
			}
			return errors.New("supervisor: winbindd exited before becoming ready")
		case <-time.After(delay):
		}

		if delay < max {
			delay *= 2
			if delay > max {
				delay = max
			}
		}
	}
}

// Done is closed once the child process has exited.
func (s *Supervisor) Done() <-chan struct{} {
	return s.done
}

// Err returns the child's exit error, valid after Done is closed.
func (s *Supervisor) Err() error {
	return s.err
}

// Stop terminates the child gracefully: SIGTERM first, then SIGKILL after
// the grace period. It is safe to call more than once.
func (s *Supervisor) Stop() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	select {
	case <-s.done:
		return nil
	default:
	}

	log.Printf("Supervisor: stopping %s (pid %d)", s.path, s.cmd.Process.Pid)
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		log.Printf("Supervisor: cannot signal %s: %v", s.path, err)
	}

	select {
	case <-s.done:
		log.Printf("Supervisor: %s stopped", s.path)
		return nil
	case <-time.After(s.stopGrace):
	}

	log.Printf("Supervisor: %s did not stop within %s, killing it", s.path, s.stopGrace)
	if err := s.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("supervisor: cannot kill %s: %w", s.path, err)
	}
	<-s.done
	return nil
}

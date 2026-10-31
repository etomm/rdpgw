package supervisor

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"syscall"
)

// Dependency is a supervised process whose exit leaves the re-executed
// child unusable. *Supervisor satisfies it: once winbindd exits the gRPC
// server can no longer authenticate anyone.
type Dependency interface {
	Done() <-chan struct{}
	Err() error
}

// ChildOptions describes the unprivileged gRPC server process.
type ChildOptions struct {
	// Name labels the child in logs.
	Name string
	// Credential runs the child as this uid/gid; nil keeps the parent's.
	Credential *syscall.Credential
	// Dependency, when set, stops the child as soon as it exits.
	Dependency Dependency
}

// RunChild starts exe with args and waits for it, returning its exit code.
// The parent deliberately keeps its privileges so it can still stop the
// supervised dependency; the child is terminated when ctx is cancelled or
// the dependency exits.
func RunChild(ctx context.Context, exe string, args []string, opts ChildOptions) int {
	name := opts.Name
	if name == "" {
		name = exe
	}

	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: opts.Credential}

	if err := cmd.Start(); err != nil {
		log.Fatalf("Cannot start %s: %v", name, err)
	}
	log.Printf("Supervisor: started %s (pid %d)", name, cmd.Process.Pid)

	// The child stops gracefully when we are asked to terminate, or as
	// soon as the dependency dies.
	go func() {
		if opts.Dependency != nil {
			select {
			case <-ctx.Done():
			case <-opts.Dependency.Done():
				log.Printf("Supervisor: %s exited: %v", name, opts.Dependency.Err())
			}
		} else {
			<-ctx.Done()
		}
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			log.Printf("Supervisor: cannot signal %s: %v", name, err)
		}
	}()

	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		log.Printf("Supervisor: %s failed: %v", name, err)
		return 1
	}
	return 0
}

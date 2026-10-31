// Package serve owns the rdpgw-auth gRPC endpoint: the unix socket, the
// peer-credential gate, graceful shutdown and the optional re-exec as an
// unprivileged user.
package serve

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/service"
	"github.com/bolkedebruin/rdpgw/cmd/auth/supervisor"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"google.golang.org/grpc"
)

const protocol = "unix"

// Options configures the gRPC endpoint.
type Options struct {
	SocketAddr  string
	ServiceName string
	AllowedUIDs []int
	AllowedGIDs []int

	// User, when set, switches the gRPC server to an unprivileged user
	// after winbindd has been started. The winbind image runs rdpgw-auth
	// as root (winbindd needs samba's root-owned state) and passes
	// --serve-user rdpgw, reproducing the old su-exec step.
	User string
	// Child is the internal re-exec mode: provisioning, domain join and
	// winbindd supervision are already done by the parent process.
	Child bool
}

// Run serves the auth API. When opts.User is set and we are root it
// re-executes the binary as that user and supervises the child, so the
// parent keeps the rights to stop winbindd.
func Run(ctx context.Context, opts Options, conf config.Configuration, wb *supervisor.Supervisor) int {
	if opts.Child || opts.User == "" {
		return listenAndServe(ctx, opts, conf, wb)
	}

	u, err := user.Lookup(opts.User)
	if err != nil {
		log.Fatalf("Cannot resolve --serve-user %q: %v", opts.User, err)
	}
	uid, uidErr := strconv.Atoi(u.Uid)
	gid, gidErr := strconv.Atoi(u.Gid)
	if uidErr != nil || gidErr != nil {
		log.Fatalf("Cannot resolve the numeric uid/gid of %q", opts.User)
	}
	if os.Geteuid() == uid {
		return listenAndServe(ctx, opts, conf, wb)
	}
	if os.Geteuid() != 0 {
		log.Fatalf("--serve-user %q requires running as root", opts.User)
	}
	return runChild(ctx, opts, u, uint32(uid), uint32(gid), wb)
}

// runChild re-executes this binary as the serving user with --serve. The
// child creates the socket, so its ownership matches the previous
// su-exec/shell setup while the parent keeps the rights to stop winbindd.
func runChild(ctx context.Context, opts Options, u *user.User, uid, gid uint32, wb *supervisor.Supervisor) int {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("Cannot determine the executable path: %v", err)
	}

	groups := []uint32{gid}
	if ids, err := u.GroupIds(); err == nil && len(ids) > 0 {
		groups = groups[:0]
		for _, s := range ids {
			if n, err := strconv.Atoi(s); err == nil {
				groups = append(groups, uint32(n))
			}
		}
	}

	args := append(append([]string{}, os.Args[1:]...), "--serve")
	log.Printf("Supervisor: serving gRPC as %s (uid %d); the supervisor stays root", u.Username, uid)

	// A nil *Supervisor must not become a non-nil Dependency interface:
	// the child then simply follows the shutdown context.
	var dep supervisor.Dependency
	if wb != nil {
		dep = wb
	}

	return supervisor.RunChild(ctx, exe, args, supervisor.ChildOptions{
		Name:       fmt.Sprintf("gRPC server as %s", u.Username),
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups},
		Dependency: dep,
	})
}

// listenAndServe owns the socket and the gRPC lifecycle. It returns the
// process exit code.
func listenAndServe(ctx context.Context, opts Options, conf config.Configuration, wb *supervisor.Supervisor) int {
	ctx, stopSignals := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()

	log.Printf("Starting auth server on %s", opts.SocketAddr)
	cleanup := func() {
		if _, err := os.Stat(opts.SocketAddr); err == nil {
			if err := os.RemoveAll(opts.SocketAddr); err != nil {
				log.Printf("Cannot remove socket %s: %v", opts.SocketAddr, err)
			}
		}
	}
	cleanup()

	oldUmask := syscall.Umask(0117)
	listener, err := net.Listen(protocol, opts.SocketAddr)
	syscall.Umask(oldUmask)
	if err != nil {
		log.Printf("Cannot listen on %s: %v", opts.SocketAddr, err)
		return 1
	}

	// The daemon's own UID is always permitted; additional callers must
	// be enumerated by the operator. This stops any local user on a
	// shared host from speaking gRPC against the PAM oracle.
	allowedUIDs := append([]int{os.Getuid()}, opts.AllowedUIDs...)
	listener = newGatedListener(listener, allowedUIDs, opts.AllowedGIDs)

	server := grpc.NewServer()
	auth.RegisterAuthenticateServer(server, service.New(opts.ServiceName, conf))

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	var winbinddDone <-chan struct{}
	if wb != nil {
		winbinddDone = wb.Done()
	}

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("Auth server stopped: %v", err)
		}
	case <-winbinddDone:
		log.Printf("winbindd exited unexpectedly: %v", wb.Err())
	case <-ctx.Done():
		log.Printf("Received shutdown signal: %v", ctx.Err())
	}

	server.GracefulStop()
	cleanup()
	return 0
}

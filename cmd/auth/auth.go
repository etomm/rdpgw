package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/join"
	"github.com/bolkedebruin/rdpgw/cmd/auth/pamstack"
	"github.com/bolkedebruin/rdpgw/cmd/auth/provisioning"
	"github.com/bolkedebruin/rdpgw/cmd/auth/serve"
	"github.com/bolkedebruin/rdpgw/cmd/auth/supervisor"
	"github.com/thought-machine/go-flags"
)

var opts struct {
	ServiceName string `short:"n" long:"name" default:"rdpgw" description:"the PAM service name to use"`
	SocketAddr  string `short:"s" long:"socket" default:"/tmp/rdpgw-auth.sock" description:"the location of the socket"`
	ConfigFile  string `short:"c" long:"conf" default:"rdpgw-auth.yaml" description:"users config file for NTLM (yaml)"`
	AllowUID    []int  `long:"allow-uid" description:"additional UIDs allowed to connect to the socket; the daemon's own UID is always allowed (repeatable)"`
	AllowGID    []int  `long:"allow-gid" description:"GIDs allowed to connect to the socket (repeatable)"`

	// ServeUser switches the gRPC server to an unprivileged user after
	// winbindd has been started. The winbind image runs rdpgw-auth as
	// root (winbindd needs samba's root-owned state) and passes
	// `--serve-user rdpgw`, reproducing the old `su-exec rdpgw` step.
	ServeUser string `long:"serve-user" description:"run the gRPC server as this user after starting winbindd (requires root)"`
	// Serve is the internal child mode: provisioning, domain join and
	// winbindd supervision are already done by the parent process.
	Serve bool `long:"serve" hidden:"true" description:"internal: serve gRPC only (used by the supervisor parent)"`
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		var fErr *flags.Error
		if errors.As(err, &fErr) {
			if fErr.Type == flags.ErrHelp {
				fmt.Printf("Acknowledgements:\n")
				fmt.Printf(" - This product includes software developed by the Thomson Reuters Global Resources. (go-ntlm - https://github.com/m7913d/go-ntlm - BSD-4 License)\n")
			}
		}
		return
	}

	conf := config.Load(opts.ConfigFile)

	// Internal child mode: the parent has already provisioned the files,
	// joined the domain (Milestone 3b) and started winbindd.
	if opts.Serve {
		os.Exit(serve.Run(context.Background(), serveOptions(), conf, nil))
	}

	// Stage and reconcile samba/kerberos files before any join or
	// supervision happens. Without winbind capability this is a no-op.
	if err := provisioning.Provision(conf); err != nil {
		log.Fatalf("Provisioning failed: %v", err)
	}

	// Generate the PAM stack for the Basic protocol (no-op when disabled).
	if err := pamstack.Install(conf, pamstack.DefaultPaths(opts.ServiceName), opts.ServeUser); err != nil {
		log.Fatalf("PAM provisioning failed: %v", err)
	}

	// SIGTERM/SIGINT must reach the shutdown path: it stops winbindd and
	// removes the socket instead of leaving both behind for the next pod.
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()

	// winbindd supervision only applies when the deployment actually
	// needs winbind (Kerberos keytab share or the winbind NTLM backend);
	// otherwise the daemon is a plain local-auth service. The external
	// mode (host-provided winbind) only waits for readiness: the host owns
	// the join state and the winbindd process.
	var winbindd *supervisor.Supervisor
	if provisioning.UsesWinbind(conf) {
		if conf.Winbind == nil {
			log.Fatalf("Winbind capability requested but the Winbind configuration block is missing")
		}
		if !supervisor.External() {
			if err := join.New(conf).Ensure(ctx); err != nil {
				if ctx.Err() != nil {
					log.Printf("Shutdown requested during Active Directory provisioning")
					return
				}
				log.Fatalf("Active Directory provisioning failed: %v", err)
			}
		}
		winbindd = supervisor.New()
		if supervisor.External() {
			log.Printf("Supervisor: external winbindd mode, not starting a child")
			readyCtx, cancel := context.WithTimeout(ctx, supervisor.ExternalReadyTimeout)
			err := winbindd.WaitReady(readyCtx)
			cancel()
			if err != nil {
				log.Fatalf("External winbindd is not responding: %v", err)
			}
		} else {
			if err := winbindd.Start(); err != nil {
				log.Fatalf("%v", err)
			}
			if err := winbindd.WaitReady(ctx); err != nil {
				_ = winbindd.Stop()
				log.Fatalf("%v", err)
			}
		}
	}

	code := serve.Run(ctx, serveOptions(), conf, winbindd)

	if winbindd != nil {
		if err := winbindd.Stop(); err != nil {
			log.Printf("Stopping winbindd: %v", err)
		}
	}
	os.Exit(code)
}

// serveOptions maps the CLI flags onto the serving package options.
func serveOptions() serve.Options {
	return serve.Options{
		SocketAddr:  opts.SocketAddr,
		ServiceName: opts.ServiceName,
		AllowedUIDs: opts.AllowUID,
		AllowedGIDs: opts.AllowGID,
		User:        opts.ServeUser,
		Child:       opts.Serve,
	}
}

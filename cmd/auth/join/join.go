// Package join implements the rdpgw-auth Active Directory integration: the
// `net ads testjoin` pre-check, the autoJoin retry loop with the join
// credentials, the operator-driven manual wait, and the shared keytab/SPN
// maintenance that follows the join.
package join

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

const (
	// Environment variables the wrapper used before Milestone 3; kept for
	// drop-in compatibility with existing Kubernetes secrets.
	adJoinUserEnv     = "AD_JOIN_USER"
	adJoinPasswordEnv = "AD_JOIN_PASSWORD"

	joinRetryInitial = 2 * time.Second
	joinRetryMax     = 30 * time.Second
	joinPollInterval = 2 * time.Second

	// defaultJoinTimeoutMinutes bounds both the auto-join retries and the
	// manual-join wait when the configuration leaves joinTimeout unset.
	defaultJoinTimeoutMinutes = 10

	// netBinary performs the testjoin/join/keytab/setspn operations.
	netBinary = "net"
)

// ErrJoinUnavailable reports that the host is not joined to Active Directory
// and the configured policy could not join it (missing credentials or the
// join budget elapsed). The message contains the operator playbook.
var ErrJoinUnavailable = errors.New("rdpgw-auth: host is not joined to Active Directory")

// runCommand executes an external command and returns a wrapped error with
// combined output on failure. Replaced in tests.
var runCommand = func(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (output: %q)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Joiner implements the Milestone 3 domain-join policy:
//   - `net ads testjoin` pre-check; a joined host is left alone;
//   - autoJoin=false: log manual instructions and wait up to the join budget
//     for an operator-initiated join, then fail with the same instructions;
//   - autoJoin=true: retry `net ads join` with exponential backoff bounded by
//     the join budget, using AD_JOIN_USER / AD_JOIN_PASSWORD.
type Joiner struct {
	winbind config.WinbindConfig
	// spns maintains the shared keytab and the registered SPNs after the join.
	spns *SPNManager

	// timeout is the join budget (joinTimeout minutes, default 10).
	timeout time.Duration
	// poll is the testjoin poll interval in the wait loop.
	poll time.Duration
	// backoffInitial/backoffMax bound the auto-join retry backoff.
	backoffInitial time.Duration
	backoffMax     time.Duration

	run func(ctx context.Context, name string, args ...string) error
	env func(string) string
}

// New builds a Joiner for the deployment. It owns both the join policy and
// the keytab/SPN maintenance that follows a successful join.
func New(conf config.Configuration) *Joiner {
	cfg := config.WinbindConfig{}
	if conf.Winbind != nil {
		cfg = *conf.Winbind
	}
	minutes := cfg.JoinTimeout
	if minutes <= 0 {
		minutes = defaultJoinTimeoutMinutes
	}
	return &Joiner{
		winbind:        cfg,
		spns:           NewSPNManager(conf),
		timeout:        time.Duration(minutes) * time.Minute,
		poll:           joinPollInterval,
		backoffInitial: joinRetryInitial,
		backoffMax:     joinRetryMax,
		run:            runCommand,
		env:            os.Getenv,
	}
}

// Ensure runs the configured join policy and, when the deployment shares a
// Kerberos keytab, refreshes and verifies the SPNs that follow the join. It
// is the single entry point used by the daemon.
func (j *Joiner) Ensure(ctx context.Context) error {
	if err := j.EnsureJoined(ctx); err != nil {
		return fmt.Errorf("domain join: %w", err)
	}
	if j.spns != nil {
		if err := j.spns.EnsureSPNs(ctx); err != nil {
			return fmt.Errorf("SPN provisioning: %w", err)
		}
	}
	return nil
}

// EnsureJoined verifies or establishes the AD domain join. A nil error means
// the host is joined and winbind may be started.
func (j *Joiner) EnsureJoined(ctx context.Context) error {
	if j.isJoined(ctx) {
		log.Printf("Domain join: host is already joined to Active Directory")
		return nil
	}

	budget, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()

	if !j.winbind.AutoJoin {
		return j.waitForManualJoin(budget)
	}
	return j.autoJoin(budget)
}

func (j *Joiner) isJoined(ctx context.Context) bool {
	if err := j.run(ctx, netBinary, "ads", "testjoin"); err != nil {
		log.Printf("Domain join: net ads testjoin failed: %v", err)
		return false
	}
	return true
}

// waitForManualJoin implements autoJoin=false: explain how to join, then
// wait for the operator until the join budget expires.
func (j *Joiner) waitForManualJoin(ctx context.Context) error {
	j.logManualInstructions("host is not joined to Active Directory; waiting for a manual join")
	ticker := time.NewTicker(j.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return j.failure("timed out waiting for the manual domain join")
		case <-ticker.C:
			if j.isJoined(ctx) {
				log.Printf("Domain join: manual join detected, continuing")
				return nil
			}
		}
	}
}

// autoJoin implements autoJoin=true: retry `net ads join` with exponential
// backoff until the join budget expires.
func (j *Joiner) autoJoin(ctx context.Context) error {
	user, password := j.env(adJoinUserEnv), j.env(adJoinPasswordEnv)
	if user == "" || password == "" {
		return j.failure(fmt.Sprintf(
			"auto-join is enabled but %s/%s are not set", adJoinUserEnv, adJoinPasswordEnv))
	}

	backoff := j.backoffInitial
	attempt := 0
	for {
		attempt++
		err := j.run(ctx, netBinary, "ads", "join", "-U", user+"%"+password)
		if err == nil && j.isJoined(ctx) {
			log.Printf("Domain join: joined the domain on attempt %d", attempt)
			return nil
		}
		if err != nil {
			log.Printf("Domain join: attempt %d failed: %v", attempt, err)
		}

		select {
		case <-ctx.Done():
			return j.failure(fmt.Sprintf("could not join the domain after %d attempt(s)", attempt))
		case <-time.After(backoff):
		}
		if backoff < j.backoffMax {
			backoff *= 2
			if backoff > j.backoffMax {
				backoff = j.backoffMax
			}
		}
	}
}

// logManualInstructions emits the operator playbook exactly once at the
// start of a wait, matching the legacy wrapper's first log message.
func (j *Joiner) logManualInstructions(reason string) {
	domain := j.winbind.Domain
	if domain == "" {
		domain = j.winbind.Workgroup
	}
	log.Printf("Domain join: %s", reason)
	log.Printf("Domain join: join domain %q by executing inside this container:", domain)
	log.Printf("    net ads join -U Administrator")
	log.Printf("or provide %s and %s (with autoJoin: true) so the daemon can do it", adJoinUserEnv, adJoinPasswordEnv)
	log.Printf("Domain join: waiting up to %s for the join before giving up", j.timeout)
}

func (j *Joiner) failure(reason string) error {
	return fmt.Errorf("%w: %s. Remediation:\n"+
		"  1. join manually inside the container: net ads join -U Administrator\n"+
		"  2. or set %s and %s with autoJoin: true\n"+
		"  3. or raise winbind.joinTimeout if the domain is slow to respond",
		ErrJoinUnavailable, reason, adJoinUserEnv, adJoinPasswordEnv)
}

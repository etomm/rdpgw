// Package service implements the rdpgw-auth API: PAM authentication and
// NTLM verification through the configured backend chain.
package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
	"github.com/bolkedebruin/rdpgw/cmd/auth/database"
	"github.com/bolkedebruin/rdpgw/cmd/auth/ntlm"
	"github.com/bolkedebruin/rdpgw/shared/auth"
	"github.com/msteinert/pam/v2"
	"github.com/samber/lo"
)

// AuthService serves PAM and NTLM authentication over gRPC.
type AuthService struct {
	auth.UnimplementedAuthenticateServer

	serviceName string
	ntlm        *ntlm.NTLMAuth
}

var _ auth.AuthenticateServer = (*AuthService)(nil)

// New builds the auth service for the given PAM service name and loaded
// configuration.
func New(serviceName string, conf config.Configuration) auth.AuthenticateServer {
	return &AuthService{
		serviceName: serviceName,
		ntlm:        ntlm.NewNTLMAuthWithBackend(newNtlmBackend(conf)),
	}
}

// newNtlmBackend maps AuthProtocols.Ntlm onto NTLM verifiers. Backends
// entries map to verifiers in order: "winbind" to Samba's ntlm_auth helper
// (which asks the domain controller via winbindd; the gateway never sees
// any password), "users" to the in-process verifier fed by the Users list.
// A configuration with a single usable backend returns that backend
// directly; multiple usable backends are chained with the ordered
// alternative/exclusive execution. Whenever NTLM is unusable — the protocol
// is not configured, explicitly disabled, or no listed backend could be
// built — an explicit-denial NullBackend is installed so the auth service
// stays up and reports the misconfiguration instead of silently falling
// back to another verifier.
func newNtlmBackend(conf config.Configuration) ntlm.Backend {
	ntlmProto := conf.AuthProtocols
	switch {
	case ntlmProto == nil || ntlmProto.Ntlm == nil:
		// AuthProtocols absent, or only other protocols (e.g. Kerberos) enabled.
		return &ntlm.NullBackend{Reason: "AuthProtocols.Ntlm is not configured"}
	case !ntlmProto.Ntlm.Enabled:
		// Disabled means disabled: NTLM handshakes must be denied, never
		// served by a lucky fallback verifier.
		return &ntlm.NullBackend{Reason: "AuthProtocols.Ntlm is disabled by configuration"}
	default:
		var chain []ntlm.Backend
		var usingUsersBackend bool

		backends := lo.Map(ntlmProto.Ntlm.Backends, func(b string, _ int) string { return strings.ToLower(b) })
		backends = lo.Uniq(backends)

		for _, b := range backends {
			switch b {
			case config.NtlmBackendWinbind:
				w := conf.Winbind
				if w == nil {
					// Validation guarantees Winbind presence; skip defensively.
					log.Printf("NTLM: winbind backend requested but Winbind is not configured, skipping")
					continue
				}
				log.Printf("NTLM: using winbind backend (%s)", w.NtlmAuthPath)
				sep := w.Separator
				if sep == 0 {
					sep = config.DefaultSeparator
				}
				chain = append(chain, &ntlm.WinbindBackend{
					NtlmAuthPath:        w.NtlmAuthPath,
					Domain:              w.Workgroup, // legacy ntlm_auth --domain (NetBIOS workgroup)
					RequireMembershipOf: w.RequireMembershipOf,
					Timeout:             time.Duration(w.Timeout) * time.Second,
					StripDomain:         w.StripDomain,
					Separator:           sep.String(),
				})
			case config.NtlmBackendUsers, config.NtlmBackendLegacyFile:
				usingUsersBackend = true
				if len(conf.Users) > 0 {
					log.Printf("NTLM: using users backend with %d user(s)", len(conf.Users))
				} else {
					log.Printf("NTLM: warning: using users backend without users")
				}
				chain = append(chain, ntlm.NewLocalBackend(database.NewConfig(conf.Users)))
			default:
				log.Printf("NTLM: warning: unknown backend %q skipped", b)
			}
		}

		if !usingUsersBackend && len(conf.Users) > 0 {
			log.Printf("NTLM: warning: Users list is ignored with the winbind backend")
		}

		switch len(chain) {
		case 0:
			return &ntlm.NullBackend{Reason: fmt.Sprintf("AuthProtocols.Ntlm contains no usable backend (configured: %v)", backends)}
		case 1:
			return chain[0]
		default:
			return ntlm.NewOrderedBackend(chain...)
		}
	}
}

func (s *AuthService) Authenticate(ctx context.Context, message *auth.UserPass) (*auth.AuthResponse, error) {
	t, err := pam.StartFunc(s.serviceName, message.Username, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return message.Password, nil
		case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
			return "", nil
		}
		return "", errors.New("unrecognized PAM message style")
	})

	r := &auth.AuthResponse{}
	r.Authenticated = false

	if err != nil {
		log.Printf("Error authenticating user: %s due to: %s", message.Username, err)
		r.Error = err.Error()
		return r, err
	}
	defer func() {
		err := t.End()
		if err != nil {
			fmt.Fprintf(os.Stderr, "end: %v\n", err)
			os.Exit(1)
		}
	}()
	if err = t.Authenticate(0); err != nil {
		log.Printf("Authentication for user: %s failed due to: %s", message.Username, err)
		r.Error = err.Error()
		return r, nil
	}

	if err = t.AcctMgmt(0); err != nil {
		log.Printf("Account authorization for user: %s failed due to %s", message.Username, err)
		r.Error = err.Error()
		return r, nil
	}

	log.Printf("User: %s authenticated", message.Username)
	r.Authenticated = true
	return r, nil
}

func (s *AuthService) NTLM(ctx context.Context, message *auth.NtlmRequest) (*auth.NtlmResponse, error) {
	r, err := s.ntlm.Authenticate(message)

	if err != nil {
		log.Printf("[%s] NTLM failed: %s", message.Session, err)
	} else if r.Authenticated {
		log.Printf("[%s] User: %s authenticated using NTLM", message.Session, r.Username)
	} else if r.NtlmMessage != "" {
		log.Printf("[%s] Sending NTLM challenge", message.Session)
	}

	return r, err
}

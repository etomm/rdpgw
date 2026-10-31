package templates

import (
	"embed"
)

// FS embeds the configuration templates rendered by the rdpgw-auth
// initializer (see cmd/auth/init.go). The packaged templates express the
// Samba/Winbind side of the deployment: smb.conf sets up the ADS security
// model around the machine account, krb5.conf points kerberos at the
// domain's KDCs.
//
//go:embed *.tmpl
var FS embed.FS

package pamstack

import (
	"fmt"
	"strings"

	"github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/bolkedebruin/rdpgw/cmd/auth/config"
)

// hashPassword returns a SHA-512 crypt(3) hash ($6$...), the format
// pam_pwdfile / libxcrypt verify on Linux. An empty salt makes the library
// generate a random one.
func hashPassword(password string) (string, error) {
	hash, err := sha512_crypt.New().Generate([]byte(password), nil)
	if err != nil {
		return "", fmt.Errorf("pamstack: cannot hash password: %w", err)
	}
	return hash, nil
}

// GenerateUsersPwd renders the pam_pwdfile database (`username:hash` per
// line) from the static user list. Passwords are never written in clear.
func GenerateUsersPwd(users []config.UserConfig) ([]byte, error) {
	var b strings.Builder
	for _, user := range users {
		if user.Username == "" {
			return nil, fmt.Errorf("pamstack: Users entry without a username")
		}
		if strings.ContainsAny(user.Username, ":\r\n") {
			return nil, fmt.Errorf("pamstack: invalid username %q", user.Username)
		}
		hash, err := hashPassword(user.Password)
		if err != nil {
			return nil, err
		}
		b.WriteString(user.Username)
		b.WriteByte(':')
		b.WriteString(hash)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

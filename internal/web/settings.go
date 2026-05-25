package web

import (
	"context"
	"strconv"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// Server-wide setting keys, mirrored as exported constants so callers
// (other packages, tests) can use the same canonical strings.
const (
	SettingEnforceTOTP            = "enforce_2fa"
	SettingAllowSelfRegistration  = "allow_self_registration"
	SettingPasswordMinLength      = "password_min_length"
	SettingPasswordRequireClasses = "password_require_classes"
	SettingPasswordBlockCommon    = "password_block_common"
	SettingPasswordBlockUsername  = "password_block_username"
	SettingLogLevel               = "log_level"
)

// boolSetting reads a boolean DB setting. dflt is returned when the key
// is unset or the DB call fails (fail-open for non-critical paths).
func boolSetting(ctx context.Context, s store.Store, key string, dflt bool) bool {
	v, err := s.GetServerSetting(ctx, key)
	if err != nil {
		return dflt
	}
	switch v {
	case "true":
		return true
	case "false":
		return false
	default:
		return dflt
	}
}

// stringSetting reads a string DB setting. Empty / error → dflt.
func stringSetting(ctx context.Context, s store.Store, key, dflt string) string {
	v, err := s.GetServerSetting(ctx, key)
	if err != nil || v == "" {
		return dflt
	}
	return v
}

// intSetting reads an int DB setting. Unset / unparseable → dflt.
func intSetting(ctx context.Context, s store.Store, key string, dflt int) int {
	v, err := s.GetServerSetting(ctx, key)
	if err != nil {
		return dflt
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return dflt
	}
	return n
}

// enforceTOTPEnabled is the canonical reader for the enforce_2fa toggle
// used by the requireAuth middleware (issue #49). Fail-open: a DB hiccup
// should not lock everyone out.
func enforceTOTPEnabled(ctx context.Context, s store.Store) bool {
	return boolSetting(ctx, s, SettingEnforceTOTP, false)
}

// allowSelfRegistrationEffective is the read-through helper for
// /ui/register: DB row wins over the YAML default so admins can flip
// registration via the Settings UI without a restart.
func (w *Web) allowSelfRegistrationEffective(ctx context.Context) bool {
	return boolSetting(ctx, w.store, SettingAllowSelfRegistration, w.allowSelfRegistration)
}

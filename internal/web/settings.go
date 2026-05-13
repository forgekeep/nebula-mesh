package web

import (
	"context"

	"github.com/juev/nebula-mesh/internal/store"
)

// SettingEnforceTOTP is the server_settings key that toggles admin-
// enforced 2FA (issue #49). "true" forces every local operator
// without TOTP into the /ui/2fa/required enrolment gate on next login;
// anything else (including the unset default) leaves 2FA opt-in.
const SettingEnforceTOTP = "enforce_2fa"

// enforceTOTPEnabled reads the server-wide enforce_2fa setting. Returns
// false on any error (the gate should fail open: if the DB is hiccupping
// we'd rather let admins through than lock everyone out).
func enforceTOTPEnabled(ctx context.Context, s store.Store) bool {
	v, err := s.GetServerSetting(ctx, SettingEnforceTOTP)
	if err != nil {
		return false
	}
	return v == "true"
}

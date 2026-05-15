// Package auth holds shared authentication primitives used by both the API
// and the Web UI — currently the password policy (issue #48). Keeping it
// in its own package gives every password-setting code path (operator
// create, self-registration, future password-reset) a single import
// surface to validate against.
package auth

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Policy is the configurable password policy. Zero-value Policy ⇒ no
// constraints; production callers should construct via Default() and
// override individual knobs from the server config / settings table.
type Policy struct {
	MinLength      int
	RequireClasses int  // 1..4 of {lower, upper, digit, symbol}
	BlockCommon    bool // reject embedded common-passwords list
	BlockUsername  bool // reject equality / substring of username
}

// Default returns the out-of-the-box policy from the issue.
func Default() Policy {
	return Policy{
		MinLength:      10,
		RequireClasses: 3,
		BlockCommon:    true,
		BlockUsername:  true,
	}
}

// Validate reports the first rule that fails for password under policy.
// Returns nil when every rule passes. usernameLower is the lowercase form
// of the operator's username; pass "" when no username context exists
// (e.g. one-off bootstrap password). The returned error message names
// the specific rule so the UI can show actionable feedback.
func (p Policy) Validate(password, usernameLower string) error {
	if p.MinLength > 0 && len(password) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters long", p.MinLength)
	}

	if p.RequireClasses > 0 {
		var hasLower, hasUpper, hasDigit, hasSymbol bool
		for _, r := range password {
			switch {
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r):
				hasSymbol = true
			}
		}
		classes := 0
		for _, b := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
			if b {
				classes++
			}
		}
		if classes < p.RequireClasses {
			return fmt.Errorf("password must contain at least %d of: lowercase letter, uppercase letter, digit, symbol", p.RequireClasses)
		}
	}

	if p.BlockUsername && usernameLower != "" {
		pwLower := strings.ToLower(password)
		if pwLower == usernameLower {
			return errors.New("password must not be your username")
		}
		if len(usernameLower) >= 4 && strings.Contains(pwLower, usernameLower) {
			return errors.New("password must not contain your username")
		}
	}

	if p.BlockCommon && isCommonPassword(strings.ToLower(password)) {
		return errors.New("password is on the list of commonly-used passwords; choose something less guessable")
	}

	return nil
}

// HumanHint returns a human-readable description of the password policy.
// Used to provide inline guidance on password form pages.
func (p Policy) HumanHint() string {
	var hints []string

	if p.MinLength > 0 {
		hints = append(hints, fmt.Sprintf("at least %d characters", p.MinLength))
	}

	if p.RequireClasses > 0 {
		hints = append(hints, fmt.Sprintf("%d of: lowercase, uppercase, digit, symbol", p.RequireClasses))
	}

	if p.BlockCommon {
		hints = append(hints, "not a common password")
	}

	if p.BlockUsername {
		hints = append(hints, "not equal to or containing username")
	}

	if len(hints) == 0 {
		return ""
	}

	return "Password must contain " + strings.Join(hints, "; ") + "."
}

//go:embed common_passwords.txt
var commonPasswordsRaw string

var commonPasswordsSet map[string]struct{}

func init() {
	commonPasswordsSet = make(map[string]struct{}, 1024)
	for _, line := range strings.Split(commonPasswordsRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		commonPasswordsSet[line] = struct{}{}
	}
}

func isCommonPassword(lower string) bool {
	_, ok := commonPasswordsSet[lower]
	return ok
}

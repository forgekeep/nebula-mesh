package auth

import (
	"strings"
	"testing"
)

func TestPolicy_Default_AcceptsStrong(t *testing.T) {
	if err := Default().Validate("Tr0ub4dor!2026", "alice"); err != nil {
		t.Errorf("default policy unexpectedly rejected strong password: %v", err)
	}
}

func TestPolicy_RejectsBelowMinLength(t *testing.T) {
	p := Default()
	err := p.Validate("Ab1!", "alice")
	if err == nil || !strings.Contains(err.Error(), "at least 10") {
		t.Errorf("expected min-length error, got %v", err)
	}
}

func TestPolicy_RejectsInsufficientClasses(t *testing.T) {
	p := Default()
	err := p.Validate("alllowercaseonly", "alice")
	if err == nil || !strings.Contains(err.Error(), "at least 3") {
		t.Errorf("expected class-count error, got %v", err)
	}
}

func TestPolicy_AcceptsThreeClasses(t *testing.T) {
	p := Default()
	// lower + upper + digit = 3 classes, no symbol.
	if err := p.Validate("AbcdefGhij1", "alice"); err != nil {
		t.Errorf("3-class password rejected: %v", err)
	}
}

func TestPolicy_RejectsEqualsUsername(t *testing.T) {
	p := Default()
	err := p.Validate("alicealice", "alice")
	if err == nil {
		t.Error("expected error for password equal to username")
	}
}

func TestPolicy_RejectsUsernameSubstring(t *testing.T) {
	p := Default()
	err := p.Validate("MyAlicePass1!", "alice")
	if err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("expected username-substring error, got %v", err)
	}
}

func TestPolicy_ShortUsernameNotSubstringChecked(t *testing.T) {
	// Usernames < 4 chars are skipped from substring check to avoid
	// rejecting passwords that happen to contain a short word.
	p := Default()
	if err := p.Validate("MyPa55Word!", "abc"); err != nil {
		t.Errorf("short username should not trigger substring check: %v", err)
	}
}

func TestPolicy_RejectsCommonPasswords(t *testing.T) {
	p := Default()
	// "password1234" — long enough, multiple classes via uppercase, but
	// listed in the embedded common-passwords set, so still rejected.
	err := p.Validate("Password1234", "alice")
	if err == nil {
		t.Errorf("expected common-password rejection")
	}
}

func TestPolicy_BlockCommon_OffAcceptsCommon(t *testing.T) {
	p := Policy{MinLength: 8, BlockCommon: false}
	// "password" is 8 chars, one class — short-circuits on class count
	// even with BlockCommon off, so use a longer hand-crafted entry
	// that meets the other rules but appears in the list.
	if err := p.Validate("Password1234", "alice"); err != nil {
		t.Errorf("BlockCommon=false should accept common-but-otherwise-ok password: %v", err)
	}
}

func TestPolicy_NoUsernameContext(t *testing.T) {
	p := Default()
	if err := p.Validate("Tr0ub4dor!2026", ""); err != nil {
		t.Errorf("empty username should disable substring check: %v", err)
	}
}

func TestIsCommonPassword_KnownEntries(t *testing.T) {
	for _, entry := range []string{"password", "qwerty", "123456", "welcome1", "p@ssw0rd"} {
		if !isCommonPassword(entry) {
			t.Errorf("expected %q to be flagged as common", entry)
		}
	}
}

func TestPolicy_Zero_AcceptsAnything(t *testing.T) {
	// Zero-value Policy with no rules — useful in tests / bootstrap.
	var p Policy
	if err := p.Validate("x", ""); err != nil {
		t.Errorf("zero policy unexpectedly rejected: %v", err)
	}
}

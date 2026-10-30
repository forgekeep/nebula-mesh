package nebulacompat

import (
	"errors"
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want Version
	}{
		{"1.12.0", Version{Major: 1, Minor: 12}},
		{"v1.10.3", Version{Major: 1, Minor: 10, Patch: 3}},
		{"1.12.0-rc1", Version{Major: 1, Minor: 12, Pre: "rc1"}},
		{"2.0.0-beta.2", Version{Major: 2, Pre: "beta.2"}},
	}
	for _, tt := range tests {
		got, err := ParseVersion(tt.in)
		if err != nil {
			t.Errorf("ParseVersion(%q) = %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseVersion(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestParseVersion_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "1.12", "1.12.0.1", "1.x.0", "01.12.0", "-1.12.0", "1.12.0-",
		"1.12.0-rc..1", "1.12.0-rc_1", "1.12.0+build", " 1.12.0", "1.12.0\n",
		"dev", "1.12.0-" + strings.Repeat("a", MaxVersionLen),
	} {
		if _, err := ParseVersion(in); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("ParseVersion(%q) err = %v, want ErrInvalidVersion", in, err)
		}
	}
}

func TestVersion_StringRoundTrips(t *testing.T) {
	for _, in := range []string{"1.12.0", "1.10.3", "1.12.0-rc1"} {
		v, err := ParseVersion(in)
		if err != nil {
			t.Fatal(err)
		}
		if v.String() != in {
			t.Errorf("String() = %q, want %q", v.String(), in)
		}
	}
}

func TestVersion_Less(t *testing.T) {
	ordered := []string{"1.9.9", "1.10.0-rc1", "1.10.0", "1.10.3", "1.11.0", "1.12.0-rc1", "1.12.0-rc2", "1.12.0", "2.0.0"}
	for i := 0; i < len(ordered); i++ {
		for j := 0; j < len(ordered); j++ {
			a, _ := ParseVersion(ordered[i])
			b, _ := ParseVersion(ordered[j])
			if got, want := a.Less(b), i < j; got != want {
				t.Errorf("%s.Less(%s) = %v, want %v", ordered[i], ordered[j], got, want)
			}
		}
	}
}

func TestVersion_Supported(t *testing.T) {
	for in, want := range map[string]bool{
		"1.9.9": false, "1.10.0-rc1": false, "1.10.0": true, "1.12.0": true,
	} {
		v, _ := ParseVersion(in)
		if got := v.Supported(); got != want {
			t.Errorf("%s.Supported() = %v, want %v", in, got, want)
		}
	}
}

func TestEffective(t *testing.T) {
	tests := []struct {
		name               string
		reported, operator string
		want               string
		source             Source
	}{
		{"agent wins", "1.12.0", "1.11.2", "1.12.0", SourceAgent},
		{"operator fallback", "", "1.11.2", "1.11.2", SourceOperator},
		{"bad report falls back", "garbage", "1.11.2", "1.11.2", SourceOperator},
		{"unknown", "", "", "0.0.0", SourceUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, src := Effective(tt.reported, tt.operator)
			if v.String() != tt.want || src != tt.source {
				t.Errorf("Effective = %s/%q, want %s/%q", v, src, tt.want, tt.source)
			}
		})
	}
}

func TestValidAgentOS(t *testing.T) {
	for _, os := range []string{"linux", "darwin", "windows", "freebsd"} {
		if !ValidAgentOS(os) {
			t.Errorf("ValidAgentOS(%q) = false", os)
		}
	}
	for _, os := range []string{"", "Linux", "ios", "android", "plan9", "linux/amd64"} {
		if ValidAgentOS(os) {
			t.Errorf("ValidAgentOS(%q) = true", os)
		}
	}
}

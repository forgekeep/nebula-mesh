// Package nebulacompat describes how Nebula releases differ in what a host can
// be configured with. The differences are known when nebula-mesh is built and
// are covered by tests, so they live here rather than in the database; the
// store only keeps each host's reported version and OS.
package nebulacompat

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxVersionLen bounds a version string accepted from an agent or an operator.
const MaxVersionLen = 64

// ErrInvalidVersion reports a string that is not a Nebula release version.
var ErrInvalidVersion = errors.New("invalid nebula version")

// Version is a Nebula release version, MAJOR.MINOR.PATCH with an optional
// pre-release suffix as `nebula -version` prints it.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// MinSupported is the oldest Nebula release nebula-mesh renders a full config
// for. Hosts below it, or with no known version, get the conservative config.
var MinSupported = Version{Major: 1, Minor: 10}

// ParseVersion parses "1.12.0" or "1.12.0-rc1". A leading "v", as in release
// tags, is accepted and dropped.
func ParseVersion(s string) (Version, error) {
	if s == "" || len(s) > MaxVersionLen {
		return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
	}
	core := strings.TrimPrefix(s, "v")
	var v Version
	if i := strings.IndexByte(core, '-'); i >= 0 {
		v.Pre = core[i+1:]
		core = core[:i]
		if !validPre(v.Pre) {
			return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
	}
	nums := [3]*int{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p != strconv.Itoa(n) {
			return Version{}, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
		}
		*nums[i] = n
	}
	return v, nil
}

// validPre accepts dot-separated alphanumeric identifiers with hyphens, the
// semver pre-release grammar without the numeric-identifier rules.
func validPre(s string) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for _, c := range id {
			if !isPreChar(c) {
				return false
			}
		}
	}
	return true
}

func isPreChar(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-'
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Less reports whether v is an earlier release than o. A pre-release sorts
// before its release; two pre-releases of one version compare as strings.
func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	if v.Patch != o.Patch {
		return v.Patch < o.Patch
	}
	switch {
	case v.Pre == o.Pre:
		return false
	case v.Pre == "":
		return false
	case o.Pre == "":
		return true
	default:
		return v.Pre < o.Pre
	}
}

// Supported reports whether nebula-mesh renders a full config for v.
func (v Version) Supported() bool {
	return !v.Less(MinSupported)
}

// Source says where a host's effective Nebula version came from.
type Source string

const (
	SourceUnknown  Source = ""
	SourceAgent    Source = "agent"
	SourceOperator Source = "operator"
)

// Effective picks the version config is rendered for: the one the agent
// reported, else the one the operator set. A value that does not parse is
// skipped, so a bad stored value degrades to the conservative config.
func Effective(reported, operator string) (Version, Source) {
	if v, err := ParseVersion(reported); err == nil {
		return v, SourceAgent
	}
	if v, err := ParseVersion(operator); err == nil {
		return v, SourceOperator
	}
	return Version{}, SourceUnknown
}

// agentOSes are the runtime.GOOS values nebula-agent is released for.
var agentOSes = map[string]bool{
	"darwin":  true,
	"freebsd": true,
	"linux":   true,
	"windows": true,
}

// ValidAgentOS reports whether os is one an agent can report.
func ValidAgentOS(os string) bool {
	return agentOSes[os]
}

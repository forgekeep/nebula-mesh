// Package version formats a CLI version banner.
//
// Each binary's main package declares its own ldflag-populated
// `version`, `commit`, `date` variables and passes them to Print. When the
// binary is built without ldflags (e.g. `go install`), missing fields are
// filled from runtime/debug.ReadBuildInfo where possible.
package version

import (
	"fmt"
	"io"
	"runtime/debug"
)

const (
	devVersion     = "dev"
	noCommit       = "none"
	unknownDate    = "unknown"
	shortCommitLen = 7
)

// Print writes a single-line version banner of the form
//
//	<name> <version> (<commit>, built <date>)
//
// Empty / placeholder fields are filled from runtime/debug.ReadBuildInfo
// when available so that `go install ...@latest` builds also produce a
// useful banner.
func Print(w io.Writer, name, version, commit, date string) {
	v, c, d := Resolve(version, commit, date)
	if len(c) > shortCommitLen {
		c = c[:shortCommitLen]
	}
	_, _ = fmt.Fprintf(w, "%s %s (%s, built %s)\n", name, v, c, d)
}

// Resolve returns the version triple, falling back to VCS info from the
// embedded build info when the input fields are placeholders or empty.
// Exported for testing.
func Resolve(version, commit, date string) (string, string, string) {
	if isPlaceholder(version) || isPlaceholder(commit) || isPlaceholder(date) {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if isPlaceholder(version) && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				version = bi.Main.Version
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if isPlaceholder(commit) {
						commit = s.Value
					}
				case "vcs.time":
					if isPlaceholder(date) {
						date = s.Value
					}
				}
			}
		}
	}
	if version == "" {
		version = devVersion
	}
	if commit == "" {
		commit = noCommit
	}
	if date == "" {
		date = unknownDate
	}
	return version, commit, date
}

func isPlaceholder(s string) bool {
	switch s {
	case "", devVersion, noCommit, unknownDate:
		return true
	}
	return false
}

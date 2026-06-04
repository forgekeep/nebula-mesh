package cli

import (
	"fmt"
	"net/url"
)

// validateServerURL rejects a --server value that is not a well-formed
// http(s) URL with a host. It deliberately allows private/loopback hosts:
// the CLI's whole purpose is to talk to a management server, which usually
// lives on localhost or an internal network (the default is
// http://localhost:8080). The guard stops scheme-confusion and malformed
// targets (file://, missing host, no scheme) from redirecting the operator's
// API key to an attacker-controlled endpoint — the exfil vector in #214.
func validateServerURL(serverURL string) error {
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid --server URL %q: %w", serverURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid --server URL %q: scheme must be http or https", serverURL)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("invalid --server URL %q: missing host", serverURL)
	}
	return nil
}

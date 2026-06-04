package cli

import "testing"

func TestValidateServerURL(t *testing.T) {
	valid := []string{
		"http://localhost:8080",
		"https://mgmt.example.com",
		"http://10.0.0.1:8080", // private/loopback is allowed: that's the CLI's normal target
		"https://192.168.1.5",
	}
	for _, s := range valid {
		if err := validateServerURL(s); err != nil {
			t.Errorf("validateServerURL(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"",                       // empty
		"localhost:8080",         // no scheme -> parsed as scheme "localhost", no host
		"ftp://mgmt.example.com", // wrong scheme
		"file:///etc/passwd",     // wrong scheme, exfil vector
		"http://",                // missing host
		"://nohost",              // unparseable scheme
	}
	for _, s := range invalid {
		if err := validateServerURL(s); err == nil {
			t.Errorf("validateServerURL(%q) = nil, want error", s)
		}
	}
}

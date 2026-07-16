package secretingress

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyAllows(t *testing.T) {
	tests := []struct {
		name       string
		policy     Policy
		tls        bool
		remoteAddr string
		host       string
		forwarded  string
		forwarded2 string
		want       bool
	}{
		{name: "direct TLS", policy: NewPolicy(":8080", false), tls: true, remoteAddr: "203.0.113.4:1234", host: "mesh.example.com", want: true},
		{name: "direct IPv4 loopback", policy: NewPolicy("127.0.0.1:8080", false), remoteAddr: "127.0.0.1:1234", host: "127.0.0.1:8080", want: true},
		{name: "direct IPv6 loopback", policy: NewPolicy("[::1]:8080", false), remoteAddr: "[::1]:1234", host: "[::1]:8080", want: true},
		{name: "localhost is not literal", policy: NewPolicy("localhost:8080", false), remoteAddr: "127.0.0.1:1234", host: "localhost:8080", want: false},
		{name: "spoofed forwarded header", policy: NewPolicy("127.0.0.1:8080", false), remoteAddr: "127.0.0.1:1234", host: "mesh.example.com", forwarded: "https", want: false},
		{name: "trusted local proxy", policy: NewPolicy("127.0.0.1:8080", true), remoteAddr: "127.0.0.1:1234", host: "mesh.example.com", forwarded: "https", want: true},
		{name: "trusted proxy needs loopback listener", policy: NewPolicy(":8080", true), remoteAddr: "127.0.0.1:1234", host: "mesh.example.com", forwarded: "https", want: false},
		{name: "trusted proxy needs loopback peer", policy: NewPolicy("127.0.0.1:8080", true), remoteAddr: "10.0.0.2:1234", host: "mesh.example.com", forwarded: "https", want: false},
		{name: "direct loopback remains allowed in proxy mode", policy: NewPolicy("127.0.0.1:8080", true), remoteAddr: "127.0.0.1:1234", host: "127.0.0.1:8080", forwarded: "https", want: true},
		{name: "trusted proxy rejects private public host", policy: NewPolicy("127.0.0.1:8080", true), remoteAddr: "127.0.0.1:1234", host: "10.0.0.4:8080", forwarded: "https", want: false},
		{name: "trusted proxy rejects appended proto", policy: NewPolicy("127.0.0.1:8080", true), remoteAddr: "127.0.0.1:1234", host: "mesh.example.com", forwarded: "https, http", want: false},
		{name: "trusted proxy rejects duplicate proto headers", policy: NewPolicy("127.0.0.1:8080", true), remoteAddr: "127.0.0.1:1234", host: "mesh.example.com", forwarded: "https", forwarded2: "http", want: false},
		{name: "trusted proxy rejects malformed host", policy: NewPolicy("127.0.0.1:8080", true), remoteAddr: "127.0.0.1:1234", host: "bad:host:value", forwarded: "https", want: false},
		{name: "public plaintext", policy: NewPolicy(":8080", false), remoteAddr: "203.0.113.4:1234", host: "mesh.example.com", want: false},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://mesh.example.com/import", http.NoBody)
			req.RemoteAddr = testCase.remoteAddr
			req.Host = testCase.host
			req.Header.Set("X-Forwarded-Proto", testCase.forwarded)
			if testCase.forwarded2 != "" {
				req.Header.Add("X-Forwarded-Proto", testCase.forwarded2)
			}
			if testCase.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if got := testCase.policy.Allows(req); got != testCase.want {
				t.Fatalf("Allows() = %v, want %v", got, testCase.want)
			}
		})
	}
}

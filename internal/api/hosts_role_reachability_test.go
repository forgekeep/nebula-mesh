package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
)

// TestCreateHost_RoleReachability mirrors issue #94 — a host created with
// role=lighthouse or role=relay must carry a non-empty public_ip and a
// non-zero listen_port; otherwise the host is never advertised to peers
// and the operator only notices via peer config inspection.
func TestCreateHost_RoleReachability(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	cases := []struct {
		name       string
		role       string
		publicIP   string
		listenPort int
		nebulaIP   string
		want       int
		wantSubstr string
	}{
		{
			name:       "lighthouse without public_ip is rejected",
			role:       "lighthouse",
			publicIP:   "",
			listenPort: 4242,
			nebulaIP:   "192.168.100.10",
			want:       http.StatusBadRequest,
			wantSubstr: "public_ip",
		},
		{
			name:       "lighthouse without listen_port is rejected",
			role:       "lighthouse",
			publicIP:   "203.0.113.1",
			listenPort: 0,
			nebulaIP:   "192.168.100.11",
			want:       http.StatusBadRequest,
			wantSubstr: "listen_port",
		},
		{
			name:       "relay without public_ip is rejected",
			role:       "relay",
			publicIP:   "",
			listenPort: 4242,
			nebulaIP:   "192.168.100.12",
			want:       http.StatusBadRequest,
			wantSubstr: "public_ip",
		},
		{
			name:       "relay without listen_port is rejected",
			role:       "relay",
			publicIP:   "203.0.113.2",
			listenPort: 0,
			nebulaIP:   "192.168.100.13",
			want:       http.StatusBadRequest,
			wantSubstr: "listen_port",
		},
		{
			name:       "host role allows empty reachability",
			role:       "host",
			publicIP:   "",
			listenPort: 0,
			nebulaIP:   "192.168.100.14",
			want:       http.StatusCreated,
		},
		{
			name:       "lighthouse with both fields is accepted",
			role:       "lighthouse",
			publicIP:   "203.0.113.3",
			listenPort: 4242,
			nebulaIP:   "192.168.100.15",
			want:       http.StatusCreated,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(createHostRequest{
				NetworkID:  netID,
				Name:       "h-" + strings.ReplaceAll(tc.name, " ", "-"),
				NebulaIPs:  []string{tc.nebulaIP},
				Role:       tc.role,
				PublicIP:   tc.publicIP,
				ListenPort: tc.listenPort,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
			authRequest(req)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d, body: %s", w.Code, tc.want, w.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(w.Body.String(), tc.wantSubstr) {
				t.Errorf("body = %q, want substring %q", w.Body.String(), tc.wantSubstr)
			}
			if tc.want == http.StatusCreated {
				var resp createHostResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if resp.Host.Role != models.HostRole(tc.role) {
					t.Errorf("role = %q, want %q", resp.Host.Role, tc.role)
				}
			}
		})
	}
}

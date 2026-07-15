package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/webhook"
)

type capturedEvent struct {
	scope webhook.Scope
	typ   string
	data  map[string]any
}

// fakeEmitter records events synchronously so handler-emit tests need no waits.
type fakeEmitter struct {
	mu     sync.Mutex
	events []capturedEvent
}

func (f *fakeEmitter) Emit(scope webhook.Scope, eventType string, data map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, capturedEvent{scope: scope, typ: eventType, data: data})
}

func (f *fakeEmitter) find(eventType string) (capturedEvent, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		if e.typ == eventType {
			return e, true
		}
	}
	return capturedEvent{}, false
}

func createHostForEvent(t *testing.T, srv *Server, netID string) createHostResponse {
	t.Helper()
	body, _ := json.Marshal(createHostRequest{NetworkID: netID, Name: "ev-host", NebulaIPs: []string{"192.168.100.50"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create host: %d / %s", w.Code, w.Body.String())
	}
	var ch createHostResponse
	_ = json.NewDecoder(w.Body).Decode(&ch)
	return ch
}

func TestEmit_HostBlockedAndUnblocked(t *testing.T) {
	srv, _ := newTestServer(t)
	fe := &fakeEmitter{}
	srv.WithEventEmitter(fe)

	netID := createNetwork(t, srv)
	host := createHostForEvent(t, srv, netID).Host

	for _, step := range []struct{ path, event string }{
		{"/block", "host.blocked"},
		{"/unblock", "host.unblocked"},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+host.ID+step.path, nil)
		authRequest(req)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("POST %s: %d / %s", step.path, w.Code, w.Body.String())
		}
		ev, ok := fe.find(step.event)
		if !ok {
			t.Fatalf("expected %s event after %s", step.event, step.path)
		}
		if ev.data["host_id"] != host.ID {
			t.Errorf("%s host_id = %v, want %s", step.event, ev.data["host_id"], host.ID)
		}
		if ev.scope.CAID != host.CAID {
			t.Errorf("%s scope CAID = %q, want %q", step.event, ev.scope.CAID, host.CAID)
		}
	}
}

func TestEmit_HostEnrolled(t *testing.T) {
	srv, _ := newTestServer(t)
	fe := &fakeEmitter{}
	srv.WithEventEmitter(fe)

	netID := createNetwork(t, srv)
	created := createHostForEvent(t, srv, netID)

	// Minimal enroll handshake.
	x := make([]byte, 32)
	if _, err := rand.Read(x); err != nil {
		t.Fatal(err)
	}
	xPub, err := curve25519.X25519(x, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, xPub)),
		SigningPubPEM: string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: edPub})),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(enrollBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d / %s", w.Code, w.Body.String())
	}

	ev, ok := fe.find("host.enrolled")
	if !ok {
		t.Fatal("expected host.enrolled event after enroll")
	}
	if ev.data["host_id"] != created.Host.ID {
		t.Errorf("host.enrolled host_id = %v, want %s", ev.data["host_id"], created.Host.ID)
	}
	if ev.data["fingerprint"] == "" || ev.data["fingerprint"] == nil {
		t.Error("host.enrolled missing fingerprint")
	}
	if ev.scope.CAID != created.Host.CAID {
		t.Errorf("host.enrolled scope CAID = %q, want %q", ev.scope.CAID, created.Host.CAID)
	}
}

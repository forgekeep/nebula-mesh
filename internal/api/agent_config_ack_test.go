package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigAckCapablePollAdvancesOnlyAfterSignedAck(t *testing.T) {
	srv, st := newTestServer(t)
	agentIdentity := enrolledFixture(t, srv)
	host, err := st.GetHost(t.Context(), agentIdentity.hostID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE host_agent_profiles SET config_ack_v1 = 1 WHERE host_id = ?`, host.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.BumpNetworkConfigVersion(t.Context(), host.NetworkID); err != nil {
		t.Fatal(err)
	}
	wantVersion, err := st.GetNetworkConfigVersion(t.Context(), host.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := st.GetHostConfigVersion(t.Context(), host.ID)

	poll := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, poll, agentIdentity)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, poll)
	if recorder.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", recorder.Code, recorder.Body.String())
	}
	var updates agentUpdatesResponse
	if err := json.NewDecoder(recorder.Body).Decode(&updates); err != nil {
		t.Fatal(err)
	}
	if updates.ConfigYAML == nil || updates.ConfigVersion != wantVersion {
		t.Fatalf("updates = %#v, want config version %d", updates, wantVersion)
	}
	if applied, _ := st.GetHostConfigVersion(t.Context(), host.ID); applied != before {
		t.Fatalf("poll advanced applied version from %d to %d", before, applied)
	}
	profile, err := st.GetHostAgentProfile(t.Context(), host.ID)
	if err != nil || profile.PendingConfigVersion != wantVersion {
		t.Fatalf("pending profile = %#v, %v", profile, err)
	}

	ackPath := fmt.Sprintf("/api/v1/agent/config-ack/%d", wantVersion)
	ack := httptest.NewRequest(http.MethodPost, ackPath, nil)
	signPoll(t, ack, agentIdentity)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, ack)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", recorder.Code, recorder.Body.String())
	}
	if applied, _ := st.GetHostConfigVersion(t.Context(), host.ID); applied != wantVersion {
		t.Fatalf("applied version = %d, want %d", applied, wantVersion)
	}
	profile, _ = st.GetHostAgentProfile(t.Context(), host.ID)
	if profile.PendingConfigVersion != 0 {
		t.Fatalf("pending version after ack = %d", profile.PendingConfigVersion)
	}

	// A fresh nonce makes response-loss retry idempotent after the first ack
	// committed but its response was not observed by the agent.
	retry := httptest.NewRequest(http.MethodPost, ackPath, nil)
	signPoll(t, retry, agentIdentity)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, retry)
	if recorder.Code != http.StatusOK {
		t.Fatalf("idempotent ack retry: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestConfigAckRejectsUnsignedFutureAndImporting(t *testing.T) {
	srv, st := newTestServer(t)
	agentIdentity := enrolledFixture(t, srv)
	host, _ := st.GetHost(t.Context(), agentIdentity.hostID)
	_, _ = st.DB().Exec(`UPDATE host_agent_profiles SET config_ack_v1 = 1, pending_config_version = 2 WHERE host_id = ?`, host.ID)

	unsigned := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/2", nil)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, unsigned)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unsigned ack status = %d", recorder.Code)
	}
	future := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/3", nil)
	signPoll(t, future, agentIdentity)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, future)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("future ack status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	wrongHost := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/2", nil)
	signPoll(t, wrongHost, agentIdentity, withPrivateKey(wrongPrivate))
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, wrongHost)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-host ack status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	const replayNonce = "fixed-config-ack-nonce"
	valid := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/2", nil)
	signPoll(t, valid, agentIdentity, withNonce(replayNonce))
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, valid)
	if recorder.Code != http.StatusOK {
		t.Fatalf("valid ack status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	replayed := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/2", nil)
	signPoll(t, replayed, agentIdentity, withNonce(replayNonce))
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, replayed)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("replayed ack status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	_, _ = st.DB().Exec(`UPDATE host_agent_profiles SET pending_config_version = 4 WHERE host_id = ?`, host.ID)
	stale := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/2", nil)
	signPoll(t, stale, agentIdentity)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, stale)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale ack status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := st.UpdateHostStatus(t.Context(), host.ID, "importing"); err != nil {
		t.Fatal(err)
	}
	importing := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/4", nil)
	signPoll(t, importing, agentIdentity)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, importing)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("importing ack status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := st.UpdateHostStatus(t.Context(), host.ID, "blocked"); err != nil {
		t.Fatal(err)
	}
	blocked := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config-ack/4", nil)
	signPoll(t, blocked, agentIdentity)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, blocked)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("blocked ack status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestConfigAckPendingDeliveryTracksNewestNetworkVersion(t *testing.T) {
	srv, st := newTestServer(t)
	agentIdentity := enrolledFixture(t, srv)
	host, _ := st.GetHost(t.Context(), agentIdentity.hostID)
	_, _ = st.DB().Exec(`UPDATE host_agent_profiles SET config_ack_v1 = 1 WHERE host_id = ?`, host.ID)

	pollVersion := func() int {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
		signPoll(t, request, agentIdentity)
		recorder := httptest.NewRecorder()
		srv.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("poll: %d %s", recorder.Code, recorder.Body.String())
		}
		var response agentUpdatesResponse
		_ = json.NewDecoder(recorder.Body).Decode(&response)
		return response.ConfigVersion
	}
	if err := st.BumpNetworkConfigVersion(t.Context(), host.NetworkID); err != nil {
		t.Fatal(err)
	}
	older := pollVersion()
	if err := st.BumpNetworkConfigVersion(t.Context(), host.NetworkID); err != nil {
		t.Fatal(err)
	}
	newer := pollVersion()
	if newer <= older {
		t.Fatalf("versions older=%d newer=%d", older, newer)
	}
	profile, _ := st.GetHostAgentProfile(t.Context(), host.ID)
	if profile.PendingConfigVersion != newer {
		t.Fatalf("pending version = %d, want newest %d", profile.PendingConfigVersion, newer)
	}
	stale := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/agent/config-ack/%d", older), nil)
	signPoll(t, stale, agentIdentity)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, stale)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale ack: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestConfigAckPendingVersionRedeliversWhenAppliedIsCurrent(t *testing.T) {
	srv, st := newTestServer(t)
	agentIdentity := enrolledFixture(t, srv)
	host, err := st.GetHost(t.Context(), agentIdentity.hostID)
	if err != nil {
		t.Fatal(err)
	}
	networkVersion, err := st.GetNetworkConfigVersion(t.Context(), host.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateHostConfigVersion(t.Context(), host.ID, networkVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE host_agent_profiles
		SET config_ack_v1 = 1, pending_config_version = ? WHERE host_id = ?`, networkVersion, host.ID); err != nil {
		t.Fatal(err)
	}

	poll := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, poll, agentIdentity)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, poll)
	if recorder.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", recorder.Code, recorder.Body.String())
	}
	var updates agentUpdatesResponse
	if err := json.NewDecoder(recorder.Body).Decode(&updates); err != nil {
		t.Fatal(err)
	}
	if updates.ConfigYAML == nil || updates.ConfigVersion != networkVersion {
		t.Fatalf("updates = %#v, want pending config version %d", updates, networkVersion)
	}

	ack := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/agent/config-ack/%d", networkVersion), nil)
	signPoll(t, ack, agentIdentity)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, ack)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", recorder.Code, recorder.Body.String())
	}
	profile, err := st.GetHostAgentProfile(t.Context(), host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if profile.PendingConfigVersion != 0 {
		t.Fatalf("pending config version = %d, want 0", profile.PendingConfigVersion)
	}
}

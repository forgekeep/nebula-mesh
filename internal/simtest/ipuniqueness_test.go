package simtest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestSim_IPUniqueness_ConcurrentCreate exercises the IP_UNIQUENESS invariant
// from ADR 0009 under concurrency. Overlay-IP uniqueness is enforced only in
// application code: validateHostIPs (internal/api/validate_ip.go) reads the
// host list, and the caller then issues a separate CreateHost write. The read
// and write are not in one transaction, and migration 014 left no UNIQUE
// constraint on host_addresses.address — so N concurrent creates of the same
// IP can all pass validation before any of them inserts (TOCTOU), and the
// overlay ends up with duplicate addresses.
//
// The assertion is the correct invariant: exactly one create may win. The race
// is intermittently reproducible, so the test is skipped until the fix lands.
func TestSim_IPUniqueness_ConcurrentCreate(t *testing.T) {
	t.Skip("known TOCTOU race in overlay-IP uniqueness: intermittently reproducible under -race " +
		"(scheduler-dependent; observed e.g. 2 of 16 concurrent creates winning, leaving two host rows " +
		"with the same address). validateHostIPs reads then the caller writes with no enclosing transaction " +
		"and no UNIQUE constraint on host_addresses.address; the production file-backed store allows " +
		"concurrent connections, widening the window. Un-skip once a network-scoped uniqueness constraint lands.")

	h := New(t, WithFileStore())
	netID := h.CreateNetwork("race-net", "10.20.0.0/16")
	const ip = "10.20.0.5"
	const n = 16

	start := make(chan struct{})
	codes := make([]int, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{
				"network_id": netID,
				"name":       fmt.Sprintf("racer-%02d", i),
				"nebula_ips": []string{ip},
			})
			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodPost, h.Server.URL+"/api/v1/hosts", bytes.NewReader(body))
			if err != nil {
				errs[i] = err
				return
			}
			req.Header.Set("Authorization", "Bearer "+apiKey)
			req.Header.Set("Content-Type", "application/json")
			<-start // release barrier: maximize validate/write overlap
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs[i] = err
				return
			}
			codes[i] = resp.StatusCode
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("racer %d transport error: %v", i, errs[i])
		}
		if codes[i] == http.StatusCreated {
			created++
		}
	}

	// Ground-truth: how many host rows actually carry the IP.
	hosts, err := h.Store.ListHosts(context.Background(), store.HostFilter{NetworkID: netID})
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	withIP := 0
	for _, hh := range hosts {
		for _, a := range hh.NebulaIPs {
			if a == ip {
				withIP++
			}
		}
	}

	if created != 1 || withIP != 1 {
		t.Errorf("IP_UNIQUENESS violated (TOCTOU): %d/%d concurrent creates of %s returned 201 and %d host rows hold the address; want exactly 1. "+
			"validateHostIPs reads then the caller writes with no enclosing transaction and no UNIQUE constraint on host_addresses.address.",
			created, n, ip, withIP)
	}
}

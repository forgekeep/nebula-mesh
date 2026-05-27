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

// TestSim_IPUniqueness_ConcurrentUpdate extends the IP_UNIQUENESS check to the
// UPDATE path. handleUpdateHost validates via validateHostIPs then writes via a
// separate UpdateHost (internal/api/hosts.go) — the same validate-then-write
// pattern as the create path. N hosts with distinct IPs concurrently PATCH to
// one target IP; the invariant is that exactly one ends up holding it.
//
// NOTE: in-process these requests usually serialize at validation (the losers
// are rejected before the write window), so this rarely interleaves the
// validate/write race. A pass here is therefore NOT proof the UPDATE path is
// race-free — the TOCTOU exists in source, same as the create path. The test
// is kept as a post-fix regression guard (it asserts the correct invariant).
func TestSim_IPUniqueness_ConcurrentUpdate(t *testing.T) {
	t.Log("NOTE: in-process PATCHes usually serialize at validation, so a PASS here is a " +
		"post-fix regression guard, not proof the UPDATE-path validate/write TOCTOU is closed.")
	h := New(t, WithFileStore())
	netID := h.CreateNetwork("upd-net", "10.40.0.0/16")

	const n = 12
	const target = "10.40.0.99"
	ids := make([]string, n)
	for i := range n {
		ids[i], _ = h.CreateHost(netID, fmt.Sprintf("u-%02d", i), "", fmt.Sprintf("10.40.0.%d", i+10))
	}

	start := make(chan struct{})
	codes := make([]int, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{"nebula_ips": []string{target}})
			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodPatch, h.Server.URL+"/api/v1/hosts/"+ids[i], bytes.NewReader(body))
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

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("patcher %d transport error: %v", i, errs[i])
		}
	}

	hosts, err := h.Store.ListHosts(context.Background(), store.HostFilter{NetworkID: netID})
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	withTarget := 0
	for _, hh := range hosts {
		for _, a := range hh.NebulaIPs {
			if a == target {
				withTarget++
			}
		}
	}
	if withTarget != 1 {
		t.Errorf("IP_UNIQUENESS violated on UPDATE path (TOCTOU): %d hosts hold %s after concurrent PATCH; want exactly 1. "+
			"handleUpdateHost validates via validateHostIPs then writes via a separate UpdateHost with no enclosing transaction.",
			withTarget, target)
	}
}

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"

	nebulaconfig "github.com/slackhq/nebula/config"

	"github.com/forgekeep/nebula-mesh/internal/fsutil"
	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// changedRestartKeys lists the keys Nebula reads only at startup whose value
// differs between the config on disk and candidate. It must run before the
// candidate replaces the file. With no readable old config there is nothing
// to compare, and whatever starts Nebula next reads the new file.
func changedRestartKeys(path, candidate string) []string {
	oldYAML, err := os.ReadFile(path) // #nosec G304 -- operator-controlled nebula config path from agent config, documented API contract
	if err != nil {
		return nil
	}
	previous := nebulaconfig.NewC(discardLogger())
	if err := previous.LoadString(string(oldYAML)); err != nil {
		return nil
	}
	next := nebulaconfig.NewC(discardLogger())
	if err := next.LoadString(candidate); err != nil {
		return nil
	}
	var changed []string
	for _, key := range nebulacompat.RestartKeys(runtime.GOOS) {
		if !reflect.DeepEqual(previous.Get(key), next.Get(key)) {
			changed = append(changed, key)
		}
	}
	return changed
}

// applyRestart runs the restart command for a config that changed restart-only
// keys and reports whether it took the place of the reload. A host with no
// command, or whose command failed, keeps the reload so reloadable changes
// still apply; the file is already written, so no later poll would see the
// difference and Nebula stays on the old values until someone restarts it.
func (p *Poller) applyRestart(ctx context.Context, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	if p.restartFunc == nil {
		p.logger.Warn("config changed keys nebula reads only at startup; restart nebula to apply them", "keys", keys)
		p.markRestartPending()
		return false
	}
	if err := p.restartFunc(ctx); err != nil {
		p.logger.Warn("failed to restart nebula", "keys", keys, "error", err)
		p.markRestartPending()
		return false
	}
	p.logger.Info("nebula restarted", "keys", keys)
	if st, ok := p.loadRestartState(); ok {
		st.Restarted = true
		p.saveRestartState(st)
	}
	return true
}

// restartStateFile, under the data dir, holds a pending restart until the
// server knows about it and until Nebula has restarted, so the mark survives
// an agent restart.
const restartStateFile = "nebula-restart-pending.json"

type restartState struct {
	// PID is the nebula PID when the restart became pending; zero when no
	// PID file names one, so only the operator can clear the mark.
	PID       int  `json:"pid"`
	Reported  bool `json:"reported"`
	Restarted bool `json:"restarted"`
}

func (p *Poller) restartStatePath() string {
	return filepath.Join(p.config.DataDir, restartStateFile)
}

func (p *Poller) loadRestartState() (restartState, bool) {
	var st restartState
	raw, err := os.ReadFile(p.restartStatePath())
	if err != nil {
		return st, false
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		p.logger.Warn("discarding unreadable restart state", "error", err)
		p.dropRestartState()
		return st, false
	}
	return st, true
}

func (p *Poller) saveRestartState(st restartState) {
	raw, err := json.Marshal(st)
	if err == nil {
		err = fsutil.AtomicWriteFile(p.restartStatePath(), raw, 0o600)
	}
	if err != nil {
		p.logger.Warn("cannot save restart state", "error", err)
	}
}

func (p *Poller) dropRestartState() {
	if err := os.Remove(p.restartStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		p.logger.Warn("cannot remove restart state", "error", err)
	}
}

func (p *Poller) currentNebulaPID() int {
	if p.config.PIDFile == "" {
		return 0
	}
	pid, err := readNebulaPID(p.config.PIDFile)
	if err != nil {
		return 0
	}
	return pid
}

// markRestartPending records that Nebula still runs the old startup-only
// values. Every mark is reported anew, even over an earlier one: an operator
// may have cleared that on the server, and the server keeps the first time.
func (p *Poller) markRestartPending() {
	p.saveRestartState(restartState{PID: p.currentNebulaPID()})
}

// syncRestartPending brings the server in line with the state file. Nebula
// counts as restarted when the restart command succeeded or the PID file names
// a new process. Failures never stop the poll and are retried on the next one.
func (p *Poller) syncRestartPending(ctx context.Context) {
	st, ok := p.loadRestartState()
	if !ok {
		return
	}
	pid := p.currentNebulaPID()
	restarted := st.Restarted || (st.PID != 0 && pid != 0 && pid != st.PID)
	switch {
	case restarted && !st.Reported:
		p.dropRestartState()
	case restarted:
		if _, ok := p.postRestartState(ctx, "cleared"); ok {
			p.dropRestartState()
		}
	case !st.Reported:
		status, ok := p.postRestartState(ctx, "required")
		switch {
		case !ok:
		case status == http.StatusNotFound:
			// A server older than #400 cannot show the mark.
			p.dropRestartState()
		default:
			st.Reported = true
			p.saveRestartState(st)
		}
	}
}

// postRestartState reports state and says whether the server settled it: a
// 404 counts, since a server without the endpoint will never take the report.
func (p *Poller) postRestartState(ctx context.Context, state string) (int, bool) {
	status, err := p.postRestart(ctx, state)
	if err == nil && status != http.StatusOK && status != http.StatusNotFound {
		err = fmt.Errorf("restart report failed (HTTP %d)", status)
	}
	if err != nil {
		if msg := err.Error(); msg != p.lastRestartErr {
			p.lastRestartErr = msg
			p.logger.Warn("cannot report nebula restart state", "error", err)
		}
		return status, false
	}
	p.lastRestartErr = ""
	return status, true
}

func (p *Poller) postRestart(ctx context.Context, state string) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.config.ServerURL+"/api/v1/agent/restart-pending/"+state, http.NoBody)
	if err != nil {
		return 0, fmt.Errorf("create restart report request: %w", err)
	}
	if err := p.signRequest(request); err != nil {
		return 0, fmt.Errorf("sign restart report request: %w", err)
	}
	response, err := p.httpClient.Do(request)
	if err != nil {
		return 0, fmt.Errorf("restart report request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, nil
}

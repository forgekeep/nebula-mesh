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

// applyStartupKeys runs the restart hook for a config that changed restart-only
// keys and reports whether it took the place of the reload. With no hook, or
// when it fails, the caller reloads so reloadable changes still apply and the
// restart stays marked: the file is already written, so no later delivery
// would see the difference and Nebula keeps the old values until it restarts.
func applyStartupKeys(ctx context.Context, keys []string, restart func(context.Context) error, marks restartMarks, logger *slog.Logger) bool {
	if len(keys) == 0 {
		return false
	}
	if restart == nil {
		logger.Warn("config changed keys nebula reads only at startup; restart nebula to apply them", "keys", keys)
		marks.mark()
		return false
	}
	if err := restart(ctx); err != nil {
		logger.Warn("failed to restart nebula", "keys", keys, "error", err)
		marks.mark()
		return false
	}
	logger.Info("nebula restarted", "keys", keys)
	if st, ok := marks.load(); ok {
		st.Restarted = true
		marks.save(st)
	}
	return true
}

func restartCommandHook(command string) func(context.Context) error {
	return func(ctx context.Context) error {
		return runHookCommand(ctx, "nebula_restart_command", command)
	}
}

func (p *Poller) applyRestart(ctx context.Context, keys []string) bool {
	return applyStartupKeys(ctx, keys, p.restartFunc, p.restartMarks(), p.logger)
}

func (p *Poller) restartMarks() restartMarks {
	return restartMarks{dataDir: p.config.DataDir, pidFile: p.config.PIDFile, logger: p.logger}
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

// restartMarks reads and writes the pending-restart state file. The poller and
// re-enrollment share it; the next poll reports what either left there.
type restartMarks struct {
	dataDir string
	pidFile string
	logger  *slog.Logger
}

func (m restartMarks) path() string {
	return filepath.Join(m.dataDir, restartStateFile)
}

func (m restartMarks) load() (restartState, bool) {
	var st restartState
	raw, err := os.ReadFile(m.path()) // #nosec G304 -- fixed file name under the operator-controlled data dir
	if err != nil {
		return st, false
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		m.logger.Warn("discarding unreadable restart state", "error", err)
		m.drop()
		return st, false
	}
	return st, true
}

func (m restartMarks) save(st restartState) {
	raw, err := json.Marshal(st)
	if err == nil {
		err = fsutil.AtomicWriteFile(m.path(), raw, 0o600)
	}
	if err != nil {
		m.logger.Warn("cannot save restart state", "error", err)
	}
}

func (m restartMarks) drop() {
	if err := os.Remove(m.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		m.logger.Warn("cannot remove restart state", "error", err)
	}
}

func (m restartMarks) currentPID() int {
	if m.pidFile == "" {
		return 0
	}
	pid, err := readNebulaPID(m.pidFile)
	if err != nil {
		return 0
	}
	return pid
}

// mark records that Nebula still runs the old startup-only values. Every mark
// is reported anew, even over an earlier one: an operator may have cleared
// that on the server, and the server keeps the first time.
func (m restartMarks) mark() {
	m.save(restartState{PID: m.currentPID()})
}

// syncRestartPending brings the server in line with the state file. Nebula
// counts as restarted when the restart command succeeded or the PID file names
// a new process. Failures never stop the poll and are retried on the next one.
func (p *Poller) syncRestartPending(ctx context.Context) {
	marks := p.restartMarks()
	st, ok := marks.load()
	if !ok {
		return
	}
	pid := marks.currentPID()
	restarted := st.Restarted || (st.PID != 0 && pid != 0 && pid != st.PID)
	switch {
	case restarted && !st.Reported:
		marks.drop()
	case restarted:
		if _, ok := p.postRestartState(ctx, "cleared"); ok {
			marks.drop()
		}
	case !st.Reported:
		status, ok := p.postRestartState(ctx, "required")
		switch {
		case !ok:
		case status == http.StatusNotFound:
			// A server older than #400 cannot show the mark.
			marks.drop()
		default:
			st.Reported = true
			marks.save(st)
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

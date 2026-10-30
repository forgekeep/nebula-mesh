package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"reflect"
	"runtime"

	nebulaconfig "github.com/slackhq/nebula/config"

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
		return false
	}
	if err := p.restartFunc(ctx); err != nil {
		p.logger.Warn("failed to restart nebula", "keys", keys, "error", err)
		return false
	}
	p.logger.Info("nebula restarted", "keys", keys)
	return true
}

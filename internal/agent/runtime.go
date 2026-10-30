package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
)

// nebulaVersionTimeout bounds one `nebula -version` run.
const nebulaVersionTimeout = 5 * time.Second

// maxNebulaVersionOutput bounds what is read from `nebula -version`.
const maxNebulaVersionOutput = 4 << 10

// runtimeReportRefresh re-sends an unchanged report, so a server that lost it
// (a restore from backup, say) learns the host's release again without
// waiting for the agent to restart.
const runtimeReportRefresh = 24 * time.Hour

// runtimeReporter tells the server which Nebula release and OS this host runs
// (#400), so it can render config for that release. It runs `nebula -version`
// again only when the binary file changes, and reports when the result differs
// from the last accepted report or that report is runtimeReportRefresh old.
type runtimeReporter struct {
	binaryPath  string
	runVersion  func(ctx context.Context, binary string) ([]byte, error)
	stamp       binaryStamp
	version     string
	reported    string
	reportedAt  time.Time
	now         func() time.Time
	unsupported bool
	lastErr     string
}

// binaryStamp identifies one build of the nebula binary on disk.
type binaryStamp struct {
	path    string
	size    int64
	modTime time.Time
}

func newRuntimeReporter(binaryPath string) *runtimeReporter {
	return &runtimeReporter{binaryPath: binaryPath, runVersion: runNebulaVersion, now: time.Now}
}

func runNebulaVersion(ctx context.Context, binary string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, nebulaVersionTimeout)
	defer cancel()
	// #nosec G204 -- operator-controlled nebula binary path from agent config (or PATH lookup), run without a shell.
	cmd := exec.CommandContext(ctx, binary, "-version")
	var out bytes.Buffer
	cmd.Stdout = &cappedWriter{w: &out, n: maxNebulaVersionOutput}
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// cappedWriter keeps the first n bytes and discards the rest without failing
// the writer, so a chatty binary cannot block on a full pipe.
type cappedWriter struct {
	w io.Writer
	n int
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.n > 0 {
		keep := p
		if len(keep) > c.n {
			keep = keep[:c.n]
		}
		written, err := c.w.Write(keep)
		c.n -= written
		if err != nil {
			return written, err
		}
	}
	return len(p), nil
}

// parseNebulaVersion reads the "Version: X.Y.Z" line every supported Nebula
// release prints for -version.
func parseNebulaVersion(out []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		rest, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "Version:")
		if !ok {
			continue
		}
		v, err := nebulacompat.ParseVersion(strings.TrimSpace(rest))
		if err != nil {
			return "", err
		}
		return v.String(), nil
	}
	return "", errors.New("no Version line in nebula -version output")
}

// detect returns the installed Nebula version, re-running the binary only
// when its path, size, or modification time changed since the last run.
func (r *runtimeReporter) detect(ctx context.Context) (string, error) {
	binary := r.binaryPath
	if binary == "" {
		found, err := exec.LookPath("nebula")
		if err != nil {
			return "", fmt.Errorf("find nebula binary: %w (set nebula_binary_path in agent.yml)", err)
		}
		binary = found
	}
	info, err := os.Stat(binary)
	if err != nil {
		return "", fmt.Errorf("stat nebula binary: %w", err)
	}
	stamp := binaryStamp{path: binary, size: info.Size(), modTime: info.ModTime()}
	if r.version != "" && stamp == r.stamp {
		return r.version, nil
	}
	out, err := r.runVersion(ctx, binary)
	if err != nil {
		return "", fmt.Errorf("run %s -version: %w", binary, err)
	}
	version, err := parseNebulaVersion(out)
	if err != nil {
		return "", fmt.Errorf("parse %s -version: %w", binary, err)
	}
	r.stamp, r.version = stamp, version
	return version, nil
}

// reportRuntime sends the Nebula version and OS to the server when they
// changed since the last accepted report, or that report is old. Failures never stop the poll: the
// server keeps rendering the conservative config until a report lands.
func (p *Poller) reportRuntime(ctx context.Context) {
	r := p.runtime
	if r == nil || r.unsupported {
		return
	}
	version, err := r.detect(ctx)
	if err != nil {
		p.warnRuntimeOnce(err)
		return
	}
	key := runtime.GOOS + "/" + version
	if key == r.reported && r.now().Sub(r.reportedAt) < runtimeReportRefresh {
		return
	}
	status, err := p.postRuntime(ctx, runtime.GOOS, version)
	switch {
	case err != nil:
		p.warnRuntimeOnce(err)
	case status == http.StatusNotFound:
		// A server older than #400 has no runtime endpoint; stop asking
		// until the agent restarts.
		r.unsupported = true
		p.logger.Info("server does not accept nebula runtime reports; config stays version-agnostic")
	case status != http.StatusOK:
		p.warnRuntimeOnce(fmt.Errorf("runtime report failed (HTTP %d)", status))
	default:
		r.reported, r.reportedAt, r.lastErr = key, r.now(), ""
		p.logger.Info("reported nebula runtime", "nebula_version", version, "os", runtime.GOOS)
	}
}

// warnRuntimeOnce logs a runtime-report failure once per distinct message, so
// a host without a nebula binary does not log the same warning every poll.
func (p *Poller) warnRuntimeOnce(err error) {
	if msg := err.Error(); msg != p.runtime.lastErr {
		p.runtime.lastErr = msg
		p.logger.Warn("cannot report nebula runtime", "error", err)
	}
}

func (p *Poller) postRuntime(ctx context.Context, goos, version string) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/agent/runtime/%s/%s", p.config.ServerURL, goos, version), http.NoBody)
	if err != nil {
		return 0, fmt.Errorf("create runtime report request: %w", err)
	}
	if err := p.signRequest(request); err != nil {
		return 0, fmt.Errorf("sign runtime report request: %w", err)
	}
	response, err := p.httpClient.Do(request)
	if err != nil {
		return 0, fmt.Errorf("runtime report request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return response.StatusCode, nil
}

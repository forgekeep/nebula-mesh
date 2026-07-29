package releaseconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSystemdUnitsUsePathsForTheirDistributionLayout(t *testing.T) {
	repoRoot := repositoryRoot(t)

	for _, tc := range []struct {
		name          string
		binary        string
		referencePath string
		packagePath   string
	}{
		{
			name:          "agent",
			binary:        "nebula-agent",
			referencePath: "deploy/systemd/nebula-agent.service",
			packagePath:   "deploy/packaging/nebula-agent.service",
		},
		{
			name:          "management_server",
			binary:        "nebula-mgmt",
			referencePath: "deploy/systemd/nebula-mgmt.service",
			packagePath:   "deploy/packaging/nebula-mgmt.service",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			referenceUnit := readFile(t, filepath.Join(repoRoot, tc.referencePath))
			packageUnit := readFile(t, filepath.Join(repoRoot, tc.packagePath))

			referenceExecStart := "ExecStart=/usr/local/bin/" + tc.binary
			packageExecStart := "ExecStart=/usr/bin/" + tc.binary
			if !strings.Contains(referenceUnit, referenceExecStart) {
				t.Errorf("reference unit %s must contain %q", tc.referencePath, referenceExecStart)
			}
			if !strings.Contains(packageUnit, packageExecStart) {
				t.Errorf("package unit %s must contain %q", tc.packagePath, packageExecStart)
			}
			if want := strings.Replace(referenceUnit, referenceExecStart, packageExecStart, 1); packageUnit != want {
				t.Errorf("package unit %s must match its reference unit except ExecStart", tc.packagePath)
			}
		})
	}
}

func TestReleaseConfigRoutesSystemdUnitsByDistributionLayout(t *testing.T) {
	repoRoot := repositoryRoot(t)
	releaseConfig := readFile(t, filepath.Join(repoRoot, ".goreleaser.yml"))

	for _, tc := range []struct {
		archiveID     string
		packageID     string
		referenceUnit string
		packageUnit   string
	}{
		{
			archiveID:     "server",
			packageID:     "nebula-mgmt",
			referenceUnit: "deploy/systemd/nebula-mgmt.service",
			packageUnit:   "deploy/packaging/nebula-mgmt.service",
		},
		{
			archiveID:     "agent",
			packageID:     "nebula-agent",
			referenceUnit: "deploy/systemd/nebula-agent.service",
			packageUnit:   "deploy/packaging/nebula-agent.service",
		},
	} {
		t.Run(tc.packageID, func(t *testing.T) {
			archive := releaseConfigSection(t, releaseConfig, "archives:", tc.archiveID)
			if !strings.Contains(archive, "- "+tc.referenceUnit) {
				t.Errorf("archive %q must include reference unit %q", tc.archiveID, tc.referenceUnit)
			}

			pkg := releaseConfigSection(t, releaseConfig, "nfpms:", tc.packageID)
			if !strings.Contains(pkg, "bindir: /usr/bin") {
				t.Errorf("package %q must install its binary into /usr/bin", tc.packageID)
			}
			if !strings.Contains(pkg, "src: "+tc.packageUnit+"\n        dst: /lib/systemd/system/"+tc.packageID+".service") {
				t.Errorf("package %q must install %q into /lib/systemd/system", tc.packageID, tc.packageUnit)
			}
		})
	}
}

func TestSystemdReadmeUsesLocalBinaryPaths(t *testing.T) {
	repoRoot := repositoryRoot(t)
	readme := readFile(t, filepath.Join(repoRoot, "deploy/systemd/README.md"))

	for _, binary := range []string{"nebula-agent", "nebula-mgmt"} {
		if !strings.Contains(readme, "/usr/local/bin/"+binary) {
			t.Errorf("manual install instructions must use /usr/local/bin/%s", binary)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func releaseConfigSection(t *testing.T, config, section, id string) string {
	t.Helper()
	sectionStart := strings.Index(config, section+"\n")
	if sectionStart == -1 {
		t.Fatalf("find section %q", section)
	}
	start := strings.Index(config[sectionStart+len(section):], "\n  - id: "+id+"\n")
	if start == -1 {
		t.Fatalf("find %s entry %q", section, id)
	}

	entryStart := sectionStart + len(section) + start
	nextEntrySearchStart := entryStart + len("\n  - id: "+id+"\n")
	if end := strings.Index(config[nextEntrySearchStart:], "\n  - id: "); end != -1 {
		return config[entryStart : nextEntrySearchStart+end]
	}
	return config[entryStart:]
}

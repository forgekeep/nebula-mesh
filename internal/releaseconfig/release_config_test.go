package releaseconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

func TestReleaseChangelogGroups(t *testing.T) {
	repoRoot := repositoryRoot(t)
	releaseConfig := readFile(t, filepath.Join(repoRoot, ".goreleaser.yml"))
	groups := releaseChangelogGroups(t, releaseConfig)

	for _, tc := range []struct {
		commit string
		want   string
	}{
		{commit: "feat(auth)!: replace credential verifiers", want: "Breaking changes"},
		{commit: "fix(auth)!: revoke legacy credentials", want: "Breaking changes"},
		{commit: "perf(store)!: change credential lookup", want: "Breaking changes"},
		{commit: "feat(auth): add keyed verifiers", want: "Features"},
		{commit: "fix(auth): reject invalid verifier", want: "Bug fixes"},
		{commit: "perf(store): reduce lookup allocations", want: "Performance"},
	} {
		t.Run(tc.commit, func(t *testing.T) {
			if got := firstMatchingChangelogGroup(t, groups, tc.commit); got != tc.want {
				t.Errorf("first changelog group for %q = %q, want %q", tc.commit, got, tc.want)
			}
		})
	}
}

func TestReleaseConfigPackagesCredentialHMACCutoverGuide(t *testing.T) {
	repoRoot := repositoryRoot(t)
	releaseConfig := readFile(t, filepath.Join(repoRoot, ".goreleaser.yml"))

	archive := releaseConfigSection(t, releaseConfig, "archives:", "server")
	if !strings.Contains(archive, "- docs/upgrade-credential-hmac-cutover.md") {
		t.Error("server archive must include credential HMAC cutover guide")
	}

	pkg := releaseConfigSection(t, releaseConfig, "nfpms:", "nebula-mgmt")
	if !strings.Contains(pkg, "src: docs/upgrade-credential-hmac-cutover.md\n        dst: /usr/share/doc/nebula-mgmt/upgrade-credential-hmac-cutover.md") {
		t.Error("nebula-mgmt package must include credential HMAC cutover guide")
	}
}

func TestReleaseConfigDoesNotRepeatCredentialHMACCutoverNotice(t *testing.T) {
	repoRoot := repositoryRoot(t)
	releaseConfig := readFile(t, filepath.Join(repoRoot, ".goreleaser.yml"))

	if strings.Contains(releaseConfig, "Breaking credential-verifier upgrade:") {
		t.Error("release header must not repeat the one-time v0.12.0 credential cutover notice")
	}
}

type changelogGroup struct {
	Title  string `yaml:"title"`
	Regexp string `yaml:"regexp"`
}

type releaseConfig struct {
	Changelog struct {
		Groups []changelogGroup `yaml:"groups"`
	} `yaml:"changelog"`
}

func releaseChangelogGroups(t *testing.T, config string) []changelogGroup {
	t.Helper()
	var parsed releaseConfig
	if err := yaml.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatalf("parse .goreleaser.yml: %v", err)
	}
	if len(parsed.Changelog.Groups) == 0 {
		t.Fatal("changelog groups must not be empty")
	}
	return parsed.Changelog.Groups
}

func firstMatchingChangelogGroup(t *testing.T, groups []changelogGroup, commit string) string {
	t.Helper()
	for _, group := range groups {
		re, err := regexp.Compile(group.Regexp)
		if err != nil {
			t.Fatalf("compile changelog regexp for %q: %v", group.Title, err)
		}
		if re.MatchString(commit) {
			return group.Title
		}
	}
	t.Fatalf("no changelog group matches %q", commit)
	return ""
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

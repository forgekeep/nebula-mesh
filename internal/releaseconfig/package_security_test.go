package releaseconfig

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPostinstallMgmt_SEC_BOOTSTRAP_001_DoesNotPersistAdminKeyInSharedFile(t *testing.T) {
	script := readFile(t, filepath.Join(repositoryRoot(t), "deploy/packaging/postinstall-mgmt.sh"))
	if strings.Contains(script, "/tmp/nebula-mgmt-init.log") {
		t.Error("bootstrap instructions must not persist the admin API key in the shared temporary directory")
	}

	foundInit := false
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "nebula-mgmt init") {
			continue
		}
		foundInit = true
		if strings.ContainsAny(trimmed, "|>") || strings.Contains(trimmed, "tee ") {
			t.Errorf("bootstrap command must print the admin API key only to the terminal, got %q", trimmed)
		}
	}
	if !foundInit {
		t.Fatal("bootstrap instructions must retain the nebula-mgmt init command")
	}
}

func TestAnsibleRoles_SEC_PACKAGE_001_StageAndVerifyPackagesPrivately(t *testing.T) {
	path := filepath.Join(repositoryRoot(t), "deploy/ansible/roles/nebula_verified_package/tasks/main.yml")
	flatTasks := flattenAnsibleTasks(parseAnsibleTasks(t, readFile(t, path)))
	privateDirs := privateTempDirectories(flatTasks)
	if len(privateDirs) == 0 {
		t.Fatal("installer must create and check a private temporary directory")
	}

	firstDownload := firstTaskIndex(flatTasks, func(task ansibleTask) bool { return task.GetURL != nil })
	if firstDownload == -1 {
		t.Fatal("role must download its release package")
	}
	if firstTaskIndex(flatTasks[:firstDownload], func(task ansibleTask) bool {
		if task.Assert == nil {
			return false
		}
		return strings.Contains(strings.Join(task.Assert.That, " "), ".stat.mode == '0700'")
	}) == -1 {
		t.Error("must check staging mode before downloading")
	}
	if !hasChecksumManifestBefore(flatTasks, firstDownload) {
		t.Error("role must retrieve checksums.txt before downloading the package")
	}
	if !hasUniqueChecksumAssertionBefore(flatTasks, firstDownload) {
		t.Error("role must require exactly one checksum for the selected package before downloading it")
	}

	downloads := make(map[string]bool)
	for _, task := range flatTasks {
		if task.GetURL == nil {
			continue
		}
		download := task.GetURL
		if !strings.HasPrefix(download.Checksum, "sha256:") {
			t.Errorf("download %q must have a SHA-256 checksum", task.Name)
		}
		if !pathInsideRegisteredDirectories(download.Dest, privateDirs) {
			t.Errorf("download destination %q must be inside a private temporary directory", download.Dest)
		}
		if download.Mode != "0600" {
			t.Errorf("downloaded package mode = %q, want 0600", download.Mode)
		}
		downloads[download.Dest] = true
	}

	var foundDeb, foundRPM bool
	for _, task := range flatTasks {
		switch {
		case task.Apt != nil:
			foundDeb = true
			if !downloads[task.Apt.Deb] {
				t.Errorf("apt package %q must be a verified private download", task.Apt.Deb)
			}
		case task.Dnf != nil:
			foundRPM = true
			if !downloads[task.Dnf.Name] {
				t.Errorf("dnf package %q must be a verified private download", task.Dnf.Name)
			}
		}
	}
	if !foundDeb || !foundRPM {
		t.Errorf("role must retain both package installers: deb=%t rpm=%t", foundDeb, foundRPM)
	}
}

type ansibleTask struct {
	Name     string           `yaml:"name"`
	Register string           `yaml:"register"`
	Tempfile *ansibleTempfile `yaml:"ansible.builtin.tempfile"`
	GetURL   *ansibleGetURL   `yaml:"ansible.builtin.get_url"`
	URI      *ansibleURI      `yaml:"ansible.builtin.uri"`
	Assert   *ansibleAssert   `yaml:"ansible.builtin.assert"`
	Apt      *ansibleApt      `yaml:"ansible.builtin.apt"`
	Dnf      *ansibleDnf      `yaml:"ansible.builtin.dnf"`
	Block    []ansibleTask    `yaml:"block"`
	Always   []ansibleTask    `yaml:"always"`
}

type ansibleTempfile struct {
	State  string `yaml:"state"`
	Prefix string `yaml:"prefix"`
}

type ansibleGetURL struct {
	Dest     string `yaml:"dest"`
	Mode     string `yaml:"mode"`
	Checksum string `yaml:"checksum"`
}

type ansibleURI struct {
	URL           string `yaml:"url"`
	ReturnContent bool   `yaml:"return_content"`
}

type ansibleAssert struct {
	That []string `yaml:"that"`
}

type ansibleApt struct {
	Deb string `yaml:"deb"`
}

type ansibleDnf struct {
	Name string `yaml:"name"`
}

func parseAnsibleTasks(t *testing.T, source string) []ansibleTask {
	t.Helper()
	var tasks []ansibleTask
	if err := yaml.Unmarshal([]byte(source), &tasks); err != nil {
		t.Fatalf("parse Ansible tasks: %v", err)
	}
	if len(tasks) == 0 {
		t.Fatal("Ansible role must contain tasks")
	}
	return tasks
}

func flattenAnsibleTasks(tasks []ansibleTask) []ansibleTask {
	var flattened []ansibleTask
	for _, task := range tasks {
		flattened = append(flattened, task)
		flattened = append(flattened, flattenAnsibleTasks(task.Block)...)
		flattened = append(flattened, flattenAnsibleTasks(task.Always)...)
	}
	return flattened
}

func privateTempDirectories(tasks []ansibleTask) map[string]bool {
	directories := make(map[string]bool)
	for _, task := range tasks {
		if task.Tempfile != nil && task.Tempfile.State == "directory" && task.Tempfile.Prefix == "nebula-package-" && task.Register != "" {
			directories[task.Register] = true
		}
	}
	return directories
}

func firstTaskIndex(tasks []ansibleTask, match func(ansibleTask) bool) int {
	for i, task := range tasks {
		if match(task) {
			return i
		}
	}
	return -1
}

func hasChecksumManifestBefore(tasks []ansibleTask, end int) bool {
	for _, task := range tasks[:end] {
		if task.URI != nil && task.URI.ReturnContent && strings.HasSuffix(task.URI.URL, "/checksums.txt") {
			return true
		}
	}
	return false
}

func hasUniqueChecksumAssertionBefore(tasks []ansibleTask, end int) bool {
	for _, task := range tasks[:end] {
		if task.Assert == nil {
			continue
		}
		for _, assertion := range task.Assert.That {
			if strings.Contains(assertion, "checksum") && strings.Contains(assertion, "length == 1") {
				return true
			}
		}
	}
	return false
}

func pathInsideRegisteredDirectories(path string, directories map[string]bool) bool {
	for directory := range directories {
		if strings.Contains(path, directory+".path") {
			return true
		}
	}
	return false
}

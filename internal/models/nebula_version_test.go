package models

import (
	"encoding/json"
	"testing"
)

func TestValidateHostAdvanced_NebulaVersion(t *testing.T) {
	for _, v := range []string{"1.12.0", "v1.10.3", "1.12.0-rc1"} {
		if err := ValidateHostAdvanced(&HostAdvanced{NebulaVersion: v}); err != nil {
			t.Errorf("nebula_version %q: %v", v, err)
		}
	}
	for _, v := range []string{"latest", "1.12", "1.12.0\n"} {
		err := ValidateHostAdvanced(&HostAdvanced{NebulaVersion: v})
		if err == nil || err.Error() != "advanced.nebula_version must be a Nebula release such as 1.12.0" {
			t.Errorf("nebula_version %q: err = %v", v, err)
		}
	}
}

func TestHostDiff_AdvancedNebulaVersionChanged(t *testing.T) {
	before := &Host{Advanced: &HostAdvanced{NebulaVersion: "1.11.2"}}
	after := &Host{Advanced: &HostAdvanced{NebulaVersion: "1.12.0"}}
	diff, hasChanges, err := HostDiff(before, after)
	if err != nil || !hasChanges {
		t.Fatalf("HostDiff = %s, %v, %v", diff, hasChanges, err)
	}
	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatal(err)
	}
	change := result["advanced.nebula_version"]
	if change["before"] != "1.11.2" || change["after"] != "1.12.0" {
		t.Errorf("diff = %s", diff)
	}
}

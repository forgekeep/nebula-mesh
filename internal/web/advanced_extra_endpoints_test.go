package web

import (
	"net/url"
	"slices"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestExtraEndpoints_FormRoundTrip: the edit form rebuilds advanced from its
// fields, so a lighthouse edited through the web UI keeps its extra endpoints
// only if the form both shows and reads them back.
func TestExtraEndpoints_FormRoundTrip(t *testing.T) {
	endpoints := []string{"192.168.1.10:4242", "[2001:db8::10]:4242"}
	state := hostFormStateFromHost(&models.Host{
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		Advanced: &models.HostAdvanced{ExtraEndpoints: endpoints},
	})
	if want := "192.168.1.10:4242\n[2001:db8::10]:4242"; state.AdvExtraEndpoints != want {
		t.Fatalf("AdvExtraEndpoints = %q, want %q", state.AdvExtraEndpoints, want)
	}

	adv, err := parseAdvancedFromForm(advForm(t, url.Values{
		"adv_extra_endpoints": {" " + state.AdvExtraEndpoints + "\r\n\n"},
	}))
	if err != nil {
		t.Fatalf("parseAdvancedFromForm: %v", err)
	}
	if adv == nil || !slices.Equal(adv.ExtraEndpoints, endpoints) {
		t.Fatalf("parsed advanced = %+v, want extra endpoints %v", adv, endpoints)
	}
}

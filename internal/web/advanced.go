package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/juev/nebula-mesh/internal/models"
)

// parseAdvancedFromForm reads the `adv_*` form fields from the host
// creation form and returns a *HostAdvanced (or nil if nothing was set).
// All fields are optional; an empty form returns nil so default rendering
// remains untouched.
func parseAdvancedFromForm(r *http.Request) (*models.HostAdvanced, error) {
	adv := &models.HostAdvanced{}
	used := false

	if h := strings.TrimSpace(r.FormValue("adv_listen_host")); h != "" {
		adv.ListenHost = h
		used = true
	}
	if m := strings.TrimSpace(r.FormValue("adv_mtu")); m != "" {
		v, err := strconv.Atoi(m)
		if err != nil {
			return nil, fmt.Errorf("adv_mtu must be a number")
		}
		adv.MTU = v
		used = true
	}
	if d := strings.TrimSpace(r.FormValue("adv_tun_device")); d != "" {
		adv.TunDevice = d
		used = true
	}
	switch r.FormValue("adv_punchy") {
	case "true":
		v := true
		adv.Punchy = &v
		used = true
	case "false":
		v := false
		adv.Punchy = &v
		used = true
	}
	if raw := strings.TrimSpace(r.FormValue("adv_unsafe_routes")); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 3 || parts[1] != "via" {
				return nil, fmt.Errorf("adv_unsafe_routes line %q: expected '<CIDR> via <NEBULA_IP>'", line)
			}
			adv.UnsafeRoutes = append(adv.UnsafeRoutes, models.UnsafeRoute{Route: parts[0], Via: parts[2]})
			used = true
		}
	}

	if !used {
		return nil, nil
	}
	return adv, nil
}

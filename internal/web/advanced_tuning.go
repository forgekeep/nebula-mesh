package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// parseTuningFromForm reads the Nebula 1.12 tuning fields of the host form
// into adv and reports whether any was set.
func parseTuningFromForm(r *http.Request, adv *models.HostAdvanced) (bool, error) {
	used := false
	if v := strings.TrimSpace(r.FormValue("adv_routines")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return false, fmt.Errorf("adv_routines must be a number")
		}
		adv.Routines = n
		used = true
	}
	for _, f := range []struct {
		name string
		dst  **bool
	}{
		{"adv_udp_offloads", &adv.UDPOffloads},
		{"adv_tun_offloads", &adv.TunOffloads},
		{"adv_pin_threads", &adv.PinThreads},
		{"adv_local_api_control_enabled", &adv.LocalAPIControlEnabled},
	} {
		switch r.FormValue(f.name) {
		case "true":
			v := true
			*f.dst = &v
			used = true
		case "false":
			v := false
			*f.dst = &v
			used = true
		}
	}
	if v := strings.TrimSpace(r.FormValue("adv_pin_threads_key")); v != "" {
		adv.PinThreadsKey = v
		used = true
	}
	for _, field := range splitCommaList(r.FormValue("adv_cpu_affinity")) {
		cpu, err := strconv.Atoi(field)
		if err != nil {
			return false, fmt.Errorf("adv_cpu_affinity entry %q must be a CPU number", field)
		}
		adv.CPUAffinity = append(adv.CPUAffinity, cpu)
		used = true
	}
	if v := strings.TrimSpace(r.FormValue("adv_local_api_control_group")); v != "" {
		adv.LocalAPIControlGroup = v
		used = true
	}
	return used, nil
}

// triStateFormValue renders a tri-state override for a select field.
func triStateFormValue(p *bool) string {
	switch {
	case p == nil:
		return ""
	case *p:
		return "true"
	default:
		return "false"
	}
}

// joinInts renders a CPU list for the adv_cpu_affinity field.
func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

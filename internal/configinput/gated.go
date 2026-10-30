package configinput

import (
	"fmt"
	"slices"
	"strings"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
)

// GatedOverride is a group of advanced overrides one nebulacompat feature
// gates, with whether the host gets them rendered.
type GatedOverride struct {
	Fields  []string
	Feature nebulacompat.Feature
	Status  nebulacompat.Status
}

type gatedGroup struct {
	feature nebulacompat.Feature
	fields  func(*models.HostAdvanced) []string
	equal   func(a, b *models.HostAdvanced) bool
}

var gatedGroups = []gatedGroup{
	{
		feature: nebulacompat.FeatureOffloads,
		fields: func(a *models.HostAdvanced) (f []string) {
			if a.UDPOffloads != nil {
				f = append(f, "advanced.udp_offloads")
			}
			if a.TunOffloads != nil {
				f = append(f, "advanced.tun_offloads")
			}
			return f
		},
		equal: func(a, b *models.HostAdvanced) bool {
			return boolPtrEqual(a.UDPOffloads, b.UDPOffloads) && boolPtrEqual(a.TunOffloads, b.TunOffloads)
		},
	},
	{
		feature: nebulacompat.FeaturePinThreads,
		fields: func(a *models.HostAdvanced) (f []string) {
			if a.PinThreads != nil {
				f = append(f, "advanced.pin_threads")
			}
			if a.PinThreadsKey != "" {
				f = append(f, "advanced.pin_threads_key")
			}
			if len(a.CPUAffinity) > 0 {
				f = append(f, "advanced.cpu_affinity")
			}
			return f
		},
		equal: func(a, b *models.HostAdvanced) bool {
			return boolPtrEqual(a.PinThreads, b.PinThreads) && a.PinThreadsKey == b.PinThreadsKey &&
				slices.Equal(a.CPUAffinity, b.CPUAffinity)
		},
	},
	{
		feature: nebulacompat.FeatureLocalAPI,
		fields: func(a *models.HostAdvanced) (f []string) {
			if a.LocalAPIControlEnabled != nil {
				f = append(f, "advanced.local_api_control_enabled")
			}
			if a.LocalAPIControlGroup != "" {
				f = append(f, "advanced.local_api_control_group")
			}
			return f
		},
		equal: func(a, b *models.HostAdvanced) bool {
			return boolPtrEqual(a.LocalAPIControlEnabled, b.LocalAPIControlEnabled) &&
				a.LocalAPIControlGroup == b.LocalAPIControlGroup
		},
	},
}

// UnappliedOverrides lists the gated overrides a host has set but does not
// get rendered, with the reason, for the host page.
func UnappliedOverrides(host *models.Host) []GatedOverride {
	if host == nil || host.Advanced == nil {
		return nil
	}
	rt := HostRuntime(host)
	var out []GatedOverride
	for _, g := range gatedGroups {
		fields := g.fields(host.Advanced)
		if len(fields) == 0 {
			continue
		}
		if st := rt.Check(g.feature); !st.Rendered {
			out = append(out, GatedOverride{Fields: fields, Feature: g.feature, Status: st})
		}
	}
	return out
}

// CheckGatedOverrides rejects a gated override that after sets or changes
// relative to before when the host's known release or OS cannot use it. An
// unknown version is accepted: the override is stored and rendered once the
// host reports a release that supports it. Overrides left unchanged pass even
// if the host has since moved to a release without the feature, so a
// downgrade does not block editing other fields. before is nil for a new host.
func CheckGatedOverrides(before, after *models.Host) error {
	if after == nil || after.Advanced == nil {
		return nil
	}
	prev := &models.HostAdvanced{}
	if before != nil && before.Advanced != nil {
		prev = before.Advanced
	}
	rt := HostRuntime(after)
	for _, g := range gatedGroups {
		fields := g.fields(after.Advanced)
		if len(fields) == 0 || g.equal(prev, after.Advanced) {
			continue
		}
		if st := rt.Check(g.feature); st.Definite {
			return fmt.Errorf("%s: %s", strings.Join(fields, ", "), st.Reason)
		}
	}
	return nil
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

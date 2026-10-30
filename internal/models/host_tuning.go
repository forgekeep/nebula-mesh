package models

import (
	"fmt"
	"slices"
	"unicode"
	"unicode/utf8"
)

// Bounds on the Nebula 1.12 tuning overrides in HostAdvanced.
const (
	MaxRoutines           = 64
	MaxCPUAffinityEntries = 256
	MaxCPUIndex           = 4095
	MaxLocalAPIGroupLen   = 256
	pinThreadsKeyPID      = "pid"
	pinThreadsKeyPort     = "port"
)

// validateHostTuning checks the shape of the routines, offload, pinning and
// local API overrides. Whether the host's Nebula release can use them is a
// separate, version-aware check.
func validateHostTuning(adv *HostAdvanced) error {
	if adv.Routines < 0 || adv.Routines > MaxRoutines {
		return fmt.Errorf("advanced.routines must be between 1 and %d", MaxRoutines)
	}
	pinning := adv.PinThreads != nil || adv.PinThreadsKey != "" || len(adv.CPUAffinity) > 0
	if pinning && adv.Routines <= 1 {
		return fmt.Errorf("advanced.pin_threads, pin_threads_key and cpu_affinity need advanced.routines above 1")
	}
	switch adv.PinThreadsKey {
	case "", pinThreadsKeyPID, pinThreadsKeyPort:
	default:
		return fmt.Errorf("advanced.pin_threads_key must be pid or port")
	}
	if len(adv.CPUAffinity) > MaxCPUAffinityEntries {
		return fmt.Errorf("advanced.cpu_affinity: at most %d entries allowed", MaxCPUAffinityEntries)
	}
	for i, cpu := range adv.CPUAffinity {
		if cpu < 0 || cpu > MaxCPUIndex {
			return fmt.Errorf("advanced.cpu_affinity[%d] must be between 0 and %d", i, MaxCPUIndex)
		}
	}
	if g := adv.LocalAPIControlGroup; g != "" {
		if len(g) > MaxLocalAPIGroupLen || !utf8.ValidString(g) || hasControlRune(g) {
			return fmt.Errorf("advanced.local_api_control_group must be a group name of at most %d bytes without control characters", MaxLocalAPIGroupLen)
		}
	}
	return nil
}

func hasControlRune(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func diffHostTuning(changes map[string]map[string]any, before, after *HostAdvanced) {
	add := func(key string, b, a any) {
		changes[key] = map[string]any{"before": b, "after": a}
	}
	if before.Routines != after.Routines {
		add("advanced.routines", before.Routines, after.Routines)
	}
	if !punchyEqual(before.UDPOffloads, after.UDPOffloads) {
		add("advanced.udp_offloads", before.UDPOffloads, after.UDPOffloads)
	}
	if !punchyEqual(before.TunOffloads, after.TunOffloads) {
		add("advanced.tun_offloads", before.TunOffloads, after.TunOffloads)
	}
	if !punchyEqual(before.PinThreads, after.PinThreads) {
		add("advanced.pin_threads", before.PinThreads, after.PinThreads)
	}
	if before.PinThreadsKey != after.PinThreadsKey {
		add("advanced.pin_threads_key", before.PinThreadsKey, after.PinThreadsKey)
	}
	if !slices.Equal(before.CPUAffinity, after.CPUAffinity) {
		add("advanced.cpu_affinity", before.CPUAffinity, after.CPUAffinity)
	}
	if !punchyEqual(before.LocalAPIControlEnabled, after.LocalAPIControlEnabled) {
		add("advanced.local_api_control_enabled", before.LocalAPIControlEnabled, after.LocalAPIControlEnabled)
	}
	if before.LocalAPIControlGroup != after.LocalAPIControlGroup {
		add("advanced.local_api_control_group", before.LocalAPIControlGroup, after.LocalAPIControlGroup)
	}
}

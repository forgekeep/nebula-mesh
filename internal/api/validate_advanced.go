package api

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/juev/nebula-mesh/internal/models"
)

// validateHostAdvanced rejects obviously broken advanced overrides before they
// reach the database. It is intentionally lenient: empty / zero-value fields
// mean "inherit network default" and pass validation.
func validateHostAdvanced(adv *models.HostAdvanced) error {
	if adv == nil {
		return nil
	}
	if adv.MTU != 0 && (adv.MTU < 576 || adv.MTU > 9216) {
		return fmt.Errorf("advanced.mtu must be between 576 and 9216")
	}
	if adv.ListenHost != "" {
		if _, err := netip.ParseAddr(adv.ListenHost); err != nil {
			return fmt.Errorf("advanced.listen_host is not a valid IP: %s", err.Error())
		}
	}
	if adv.TunDevice != "" {
		if strings.ContainsAny(adv.TunDevice, " \t\n/") {
			return fmt.Errorf("advanced.tun_device must not contain whitespace or slashes")
		}
		if len(adv.TunDevice) > 32 {
			return fmt.Errorf("advanced.tun_device must be at most 32 characters")
		}
	}
	for i, r := range adv.UnsafeRoutes {
		if r.Route == "" || r.Via == "" {
			return fmt.Errorf("advanced.unsafe_routes[%d]: route and via are required", i)
		}
		if _, err := netip.ParsePrefix(r.Route); err != nil {
			return fmt.Errorf("advanced.unsafe_routes[%d].route invalid CIDR: %s", i, err.Error())
		}
		if _, err := netip.ParseAddr(r.Via); err != nil {
			return fmt.Errorf("advanced.unsafe_routes[%d].via invalid IP: %s", i, err.Error())
		}
	}
	return nil
}

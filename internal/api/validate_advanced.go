package api

import (
	"github.com/juev/nebula-mesh/internal/models"
)

// validateHostAdvanced delegates to models.ValidateHostAdvanced so the
// API and Web layers produce identical user-facing messages. Kept as a
// shim so existing call sites do not need to import models directly.
func validateHostAdvanced(adv *models.HostAdvanced) error {
	return models.ValidateHostAdvanced(adv)
}

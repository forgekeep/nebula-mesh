package models

import "time"

type Network struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDRs     []string  `json:"cidrs"`
	CAID      string    `json:"ca_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

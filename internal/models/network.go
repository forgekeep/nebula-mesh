package models

import "time"

type Network struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	CAID      string    `json:"ca_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

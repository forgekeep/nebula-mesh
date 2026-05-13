package config

import (
	"testing"
	"time"
)

func TestEnrollmentTokenTTLDuration(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"empty falls back to 24h", "", 24 * time.Hour},
		{"valid hours", "2h", 2 * time.Hour},
		{"valid mixed", "1h30m", 90 * time.Minute},
		{"invalid syntax falls back", "nonsense", 24 * time.Hour},
		{"zero falls back", "0s", 24 * time.Hour},
		{"negative falls back", "-1h", 24 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ServerConfig{EnrollmentTokenTTL: c.in}.EnrollmentTokenTTLDuration()
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

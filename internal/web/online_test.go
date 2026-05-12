package web

import (
	"testing"
	"time"
)

func TestIsHostOnline(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		lastSeen  *time.Time
		threshold time.Duration
		want      bool
	}{
		{name: "never polled", lastSeen: nil, threshold: time.Minute, want: false},
		{
			name:      "polled just now",
			lastSeen:  ptr(now),
			threshold: time.Minute,
			want:      true,
		},
		{
			name:      "polled inside threshold",
			lastSeen:  ptr(now.Add(-30 * time.Second)),
			threshold: time.Minute,
			want:      true,
		},
		{
			name:      "polled exactly at threshold (excluded)",
			lastSeen:  ptr(now.Add(-time.Minute)),
			threshold: time.Minute,
			want:      false,
		},
		{
			name:      "polled long ago",
			lastSeen:  ptr(now.Add(-1 * time.Hour)),
			threshold: time.Minute,
			want:      false,
		},
		{
			name:      "zero time",
			lastSeen:  ptr(time.Time{}),
			threshold: time.Minute,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHostOnline(tt.lastSeen, tt.threshold, now)
			if got != tt.want {
				t.Errorf("isHostOnline(%v) = %v, want %v", tt.lastSeen, got, tt.want)
			}
		})
	}
}

func ptr(t time.Time) *time.Time { return &t }

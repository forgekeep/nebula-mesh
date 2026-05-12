package web

import "time"

// hostOnlineThreshold is the wall-clock window inside which a host is
// considered "online": the most recent agent poll happened no more than
// this duration ago. Defaults to twice the default agent poll interval
// (30s), giving one missed poll of headroom before flipping to offline.
const hostOnlineThreshold = 60 * time.Second

// isHostOnline reports whether a host whose last poll happened at
// lastSeen should be rendered as "online" right now. nil / zero values
// (a host that never polled) are always offline.
func isHostOnline(lastSeen *time.Time, threshold time.Duration, now time.Time) bool {
	if lastSeen == nil || lastSeen.IsZero() {
		return false
	}
	return now.Sub(*lastSeen) < threshold
}

package web

import "time"

// timeNow is overridable in tests.
var timeNow = time.Now

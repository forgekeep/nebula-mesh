package cli

import (
	"net/http"
	"time"
)

// defaultCLIHTTPTimeout bounds a single CLI request so an unresponsive or
// unreachable management server cannot hang the command indefinitely. Mirrors
// the agent daemon's per-request timeout (#193); http.DefaultClient has none.
const defaultCLIHTTPTimeout = 30 * time.Second

// httpClient is the shared client for every CLI request. It exists solely to
// carry the timeout that http.DefaultClient lacks.
var httpClient = &http.Client{Timeout: defaultCLIHTTPTimeout}

package simtest

import (
	"fmt"
	"strings"
	"sync"
)

// Event is one entry in the simulation journal. The journal is what makes a
// fleet-scale failure legible (ADR 0009): instead of "assertion failed", a
// violated invariant prints the minimal trace of what happened to the
// entities involved.
type Event struct {
	Step   int
	Actor  string // virtual agent name, or operator action source
	Action string // enroll | poll | bump-version | block | ...
	Target string // host ID or network ID the action touched
	Status int    // HTTP status, when applicable
	Note   string // short human-readable detail
}

// Journal is a concurrency-safe append-only event log shared across a fleet.
type Journal struct {
	mu     sync.Mutex
	events []Event
}

// NewJournal returns an empty journal.
func NewJournal() *Journal { return &Journal{} }

// Add appends an event, stamping it with the next step number.
func (j *Journal) Add(e Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e.Step = len(j.events) + 1
	j.events = append(j.events, e)
}

// Report renders the journal entries touching target (a host or network ID)
// as a compact trace, for embedding in an invariant-violation failure message.
// An empty target renders the whole journal.
func (j *Journal) Report(target string) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "--- journal (target=%q) ---\n", target)
	for _, e := range j.events {
		if target != "" && e.Target != target {
			continue
		}
		fmt.Fprintf(&b, "  step %-5d %-12s %-14s target=%s", e.Step, e.Action, e.Actor, e.Target)
		if e.Status != 0 {
			fmt.Fprintf(&b, " http=%d", e.Status)
		}
		if e.Note != "" {
			fmt.Fprintf(&b, " (%s)", e.Note)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

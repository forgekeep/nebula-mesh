package api

import (
	"context"

	"github.com/juev/nebula-mesh/internal/models"
)

// actorContextKey scopes the authenticated operator on the request context.
type actorContextKeyType struct{}

var actorContextKey = actorContextKeyType{}

// ActorOf returns the operator attached to the request context. On protected
// API routes bearerAuth guarantees a non-nil value; nil indicates an
// unauthenticated context (e.g. public endpoints, tests).
func ActorOf(ctx context.Context) *models.Operator {
	op, _ := ctx.Value(actorContextKey).(*models.Operator)
	return op
}

// ActorName returns a stable string identifier for the actor, suitable for
// audit log entries. Returns "unknown" if no actor is on the context — this
// should not happen on routes guarded by bearerAuth.
func ActorName(ctx context.Context) string {
	if op := ActorOf(ctx); op != nil {
		return op.Username
	}
	return "unknown"
}

func withActor(ctx context.Context, op *models.Operator) context.Context {
	return context.WithValue(ctx, actorContextKey, op)
}

// actorIsAdmin reports whether the request's authenticated actor has the
// admin role. Returns false when no actor is on the context (fail-closed).
func actorIsAdmin(ctx context.Context) bool {
	op := ActorOf(ctx)
	return op != nil && op.Role == "admin"
}

// recordAuditAction writes an audit log entry and bumps the matching
// Prometheus audit counter. The DB write is best-effort to match prior
// fire-and-forget semantics; counter updates always run regardless of error.
func (s *Server) recordAuditAction(ctx context.Context, action, resource, details string) {
	_ = s.store.AddAuditEntry(ctx, ActorName(ctx), action, resource, details)
	s.metrics.recordAudit(action)
}

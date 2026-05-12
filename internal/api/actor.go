package api

import (
	"context"

	"github.com/juev/nebula-mesh/internal/models"
)

// actorContextKey scopes the authenticated operator on the request context.
type actorContextKeyType struct{}

var actorContextKey = actorContextKeyType{}

// ActorOf returns the operator attached to the request context, if any.
// Returns nil when the request was authenticated via the legacy config key.
func ActorOf(ctx context.Context) *models.Operator {
	op, _ := ctx.Value(actorContextKey).(*models.Operator)
	return op
}

// ActorName returns a stable string identifier for the actor, suitable for
// audit log entries. Falls back to "legacy-admin" for legacy-config-key auth.
func ActorName(ctx context.Context) string {
	if op := ActorOf(ctx); op != nil {
		return op.Username
	}
	return "legacy-admin"
}

func withActor(ctx context.Context, op *models.Operator) context.Context {
	return context.WithValue(ctx, actorContextKey, op)
}

// actorIsAdmin reports whether the request's authenticated actor has the
// admin role. The legacy config-key fallback (no operator on context) is
// also treated as admin, matching its pre-multi-operator behavior.
func actorIsAdmin(ctx context.Context) bool {
	op := ActorOf(ctx)
	if op == nil {
		return true // legacy config api_key — effectively root
	}
	return op.Role == "admin"
}

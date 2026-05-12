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

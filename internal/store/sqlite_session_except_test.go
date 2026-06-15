package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestDeleteOperatorSessionsByOperatorExcept verifies that self-service password
// change can terminate every other session of an operator while keeping the
// caller's current session alive (#259). The kept session is identified by its
// raw token; the method hashes it internally like DeleteOperatorSession.
func TestDeleteOperatorSessionsByOperatorExcept(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "erin")
	other := newTestOperator(t, s, "frank")

	mk := func(operatorID, token string) {
		t.Helper()
		if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
			Token:      token,
			OperatorID: operatorID,
			State:      models.SessionStateAuthenticated,
			ExpiresAt:  time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create session %q: %v", token, err)
		}
	}
	mk(op.ID, "keep-token")
	mk(op.ID, "drop-token-1")
	mk(op.ID, "drop-token-2")
	mk(other.ID, "other-token") // belongs to a different operator, must survive

	if err := s.DeleteOperatorSessionsByOperatorExcept(ctx, op.ID, "keep-token"); err != nil {
		t.Fatalf("delete except: %v", err)
	}

	// The kept session is still valid.
	if _, err := s.GetOperatorBySession(ctx, "keep-token"); err != nil {
		t.Errorf("kept session should be valid, got %v", err)
	}
	// The other two of this operator are gone.
	for _, tok := range []string{"drop-token-1", "drop-token-2"} {
		if _, err := s.GetOperatorBySession(ctx, tok); !errors.Is(err, ErrNotFound) {
			t.Errorf("session %q should be deleted, got err=%v", tok, err)
		}
	}
	// A different operator's session is untouched.
	if _, err := s.GetOperatorBySession(ctx, "other-token"); err != nil {
		t.Errorf("other operator's session should survive, got %v", err)
	}
}

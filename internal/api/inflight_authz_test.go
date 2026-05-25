package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// Tests for isActiveAdmin — the re-checking authz gate that closes the
// stale-captured-context window between bearerAuth and the handler's
// mutating SQL (residual-TOCTOU caveat noted in authz.go).

// mutateHandler returns a minimal admin-gated handler stub for
// exercising isActiveAdmin in isolation, without coupling tests to a
// specific real handler's body.
func mutateHandler(srv *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !srv.isActiveAdmin(r.Context()) {
			writeError(w, http.StatusForbidden, "operator management requires the admin role")
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func TestIsActiveAdmin_RejectsDisabledMidFlight(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	captured := &models.Operator{
		ID: "captured-admin", Username: "captured-admin", PasswordHash: "h",
		Role: "admin", Status: models.OperatorStatusActive, AuthProvider: models.OperatorAuthLocal,
	}
	if err := st.CreateOperator(ctx, captured); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.DisableOperator(ctx, captured.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// Sanity: the stale ctx still claims admin — the snapshot gap the
	// re-fetch closes.
	staleCtx := withActor(ctx, captured)
	if !actorIsAdmin(staleCtx) {
		t.Fatal("stale ctx should still pass the snapshot-only actorIsAdmin check")
	}

	rec := httptest.NewRecorder()
	mutateHandler(srv)(rec, httptest.NewRequest(http.MethodPost, "/m", nil).WithContext(staleCtx))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIsActiveAdmin_RejectsDeletedOperator(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	captured := &models.Operator{
		ID: "captured-deleted", Username: "captured-deleted", PasswordHash: "h",
		Role: "admin", Status: models.OperatorStatusActive, AuthProvider: models.OperatorAuthLocal,
	}
	if err := st.CreateOperator(ctx, captured); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Hard-DELETE exercises the ErrNotFound fork separately from the
	// disabled branch — the two have different error-handling paths in
	// isActiveAdmin (ErrNotFound is silent; other errors log).
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM operators WHERE id=?`, captured.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	rec := httptest.NewRecorder()
	mutateHandler(srv)(rec, httptest.NewRequest(http.MethodPost, "/m", nil).WithContext(withActor(ctx, captured)))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

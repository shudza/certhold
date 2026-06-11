package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/shudza/certhold/internal/db"
)

type healthzResponse struct {
	FleetRev  int64 `json:"fleet_rev"`
	CAVersion int   `json:"ca_version"`
}

// healthzHandler reports the fleet revision and active CA version. Both are
// non-sensitive counters, so the endpoint is unauthenticated; a database that
// has never minted a CA reports ca_version 0.
func healthzHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rev, err := database.FleetRev(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "read fleet rev failed")
			return
		}
		caVersion, err := database.ActiveCAVersion(ctx)
		if err != nil && !errors.Is(err, db.ErrNoActiveCA) {
			writeErr(w, http.StatusInternalServerError, "read ca version failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(healthzResponse{FleetRev: rev, CAVersion: caVersion})
	}
}

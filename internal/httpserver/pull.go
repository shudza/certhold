package httpserver

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/shudza/certhold/internal/clientcli"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

func pullPeer(w http.ResponseWriter, r *http.Request, database *db.DB) *db.Peer {
	peer, err := database.GetPeerByPullToken(r.Context(), r.PathValue("token"))
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			writeErr(w, http.StatusNotFound, "token not found")
		} else {
			writeErr(w, http.StatusInternalServerError, "lookup pull token failed")
		}
		return nil
	}
	if peer.Revoked {
		writeErr(w, http.StatusGone, "peer revoked")
		return nil
	}
	return peer
}

func pullHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		peer := pullPeer(w, r, database)
		if peer == nil {
			return
		}
		if len(peer.Cert) == 0 {
			writeErr(w, http.StatusConflict,
				"refresh bundle unavailable for this peer: re-enroll it or run `certhold update` on the manager")
			return
		}

		instanceKey, ok, err := database.GetMeta(ctx, db.MetaInstanceKey)
		if err != nil || !ok || instanceKey == "" {
			writeErr(w, http.StatusInternalServerError, "instance key not available")
			return
		}
		reachable, err := database.ReachableHosts(ctx, peer.Name)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "resolve reachable hosts failed")
			return
		}
		hosts := make([]peerfiles.HostEntry, 0, len(reachable))
		for _, h := range reachable {
			hosts = append(hosts, peerfiles.HostEntry{Name: h.Name, Address: h.Address, User: h.TargetUser})
		}
		rev, err := database.FleetRev(ctx)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "read fleet rev failed")
			return
		}

		bundle, err := peerfiles.BuildRefreshBundle(peerfiles.RefreshBundle{
			InstanceKey: instanceKey,
			PeerName:    peer.Name,
			CLIVersion:  clientcli.Version,
			CertPub:     peer.Cert,
			CLIScript:   clientcli.Script,
			Hosts:       hosts,
			FleetRev:    rev,
			CertSerial:  peer.Serial,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "build refresh bundle failed")
			return
		}

		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(bundle)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	}
}

func pullRevHandler(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peer := pullPeer(w, r, database)
		if peer == nil {
			return
		}
		rev, err := database.FleetRev(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "read fleet rev failed")
			return
		}
		body := fmt.Sprintf("%d\n", rev)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

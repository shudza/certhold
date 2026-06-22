package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shudza/certhold/internal/db"
	"golang.org/x/crypto/ssh"
)

type peerRow struct {
	Name          string
	Address       string
	DialHost      string
	TargetUser    string
	Fingerprint   string
	Serial        uint64
	Revoked       bool
	Inbound       bool
	PushReachable bool
	HasPullToken  bool
	CreatedAt     time.Time
	Groups        []string
	Allowed       []string
	Expires       certExpiry
}

type groupRow struct {
	Name      string
	PeerCount int
	Members   []string
	AllowedBy []string
}

type fleetData struct {
	DBPath         string
	BaseURL        string
	FleetRev       int64
	CAVersion      int
	CAVersionKnown bool
	Peers          []peerRow
	Groups         []groupRow
}

type certState int

const (
	certNone certState = iota
	certForever
	certAt
)

type certExpiry struct {
	state certState
	from  time.Time
	until time.Time
}

// parseCertExpiry reads the validity window out of a stored SSH certificate
// blob. A nil blob is a pre-feature row (certNone); an unparseable blob is
// treated the same so the dashboard never errors on malformed data.
func parseCertExpiry(blob []byte) certExpiry {
	if len(blob) == 0 {
		return certExpiry{state: certNone}
	}
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return certExpiry{state: certNone}
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return certExpiry{state: certNone}
	}
	e := certExpiry{}
	if cert.ValidAfter > 0 {
		e.from = time.Unix(int64(cert.ValidAfter), 0).UTC()
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		e.state = certForever
		return e
	}
	e.state = certAt
	e.until = time.Unix(int64(cert.ValidBefore), 0).UTC()
	return e
}

func (c certExpiry) expired() bool {
	return c.state == certAt && time.Now().After(c.until)
}

func (c certExpiry) expiringWithin(d time.Duration, now time.Time) bool {
	return c.state == certAt && now.Before(c.until) && !c.until.After(now.Add(d))
}

// readBaseURL mirrors internal/cli's LoadBaseURL (a plain base_url file in the
// data dir, which also holds the db); duplicated here so tui never imports cli,
// whose files another task edits in parallel. Absent or unreadable means unknown.
func readBaseURL(dbPath string) string {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(dbPath), "base_url"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func load(ctx context.Context, d *db.DB, dbPath string) (fleetData, error) {
	fd := fleetData{DBPath: dbPath, BaseURL: readBaseURL(dbPath)}

	rev, err := d.FleetRev(ctx)
	if err != nil {
		return fd, err
	}
	fd.FleetRev = rev

	if v, err := d.ActiveCAVersion(ctx); err == nil {
		fd.CAVersion = v
		fd.CAVersionKnown = true
	}

	peers, err := d.ListPeers(ctx)
	if err != nil {
		return fd, err
	}
	for _, p := range peers {
		groups, err := d.GetPeerGroups(ctx, p.Name)
		if err != nil {
			return fd, err
		}
		allowed, err := d.GetPeerAllowedGroups(ctx, p.Name)
		if err != nil {
			return fd, err
		}
		fd.Peers = append(fd.Peers, peerRow{
			Name:          p.Name,
			Address:       p.Address,
			DialHost:      p.DialHost(),
			TargetUser:    p.TargetUser,
			Fingerprint:   p.Fingerprint,
			Serial:        p.Serial,
			Revoked:       p.Revoked,
			Inbound:       p.Inbound,
			PushReachable: p.PushReachable,
			HasPullToken:  p.PullToken != "",
			CreatedAt:     p.CreatedAt,
			Groups:        groups,
			Allowed:       allowed,
			Expires:       parseCertExpiry(p.Cert),
		})
	}

	groups, err := d.ListGroupsWithPeerCount(ctx)
	if err != nil {
		return fd, err
	}
	for _, g := range groups {
		members, err := d.GetGroupMembers(ctx, g.Name)
		if err != nil {
			return fd, err
		}
		allowedBy, err := d.GetGroupAllowedBy(ctx, g.Name)
		if err != nil {
			return fd, err
		}
		fd.Groups = append(fd.Groups, groupRow{
			Name:      g.Name,
			PeerCount: g.PeerCount,
			Members:   members,
			AllowedBy: allowedBy,
		})
	}

	return fd, nil
}

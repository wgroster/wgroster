package store

import (
	"fmt"
	"testing"
	"time"
)

// machineFor creates an active machine owned by uid and returns it.
func machineFor(t *testing.T, s *Store, uid, name, pubKey string) *Machine {
	t.Helper()
	m := &Machine{OwnerUID: uid, Name: name, PublicKey: pubKey}
	if err := s.CreateMachine(m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Pending retention counts from the moment a machine entered the review queue.
// A long-standing machine sent back to pending (a key change, or an offboarded
// owner) must therefore get the full review window, not be swept immediately
// because it was created months ago.
func TestDeleteExpiredPendingCountsFromPendingSince(t *testing.T) {
	s := newTestStore(t)
	requeued := machineFor(t, s, "alice", "laptop", "k-alice-1")
	stale := machineFor(t, s, "bob", "laptop", "k-bob-1")

	// Age both rows: created (and queued) a week ago.
	weekAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	if _, err := s.db.Exec(`UPDATE machine SET created_at=?, pending_since=?`, weekAgo, weekAgo); err != nil {
		t.Fatal(err)
	}
	// One of them is approved and then sent back to pending right now.
	if err := s.ApproveMachine(requeued.ID, "10.0.0.5", nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMachinePending(requeued.ID); err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteExpiredPending(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d machine(s), want 1", n)
	}
	if _, err := s.GetMachine(requeued.ID); err != nil {
		t.Errorf("the freshly requeued machine was deleted: %v", err)
	}
	if _, err := s.GetMachine(stale.ID); err == nil {
		t.Error("the machine pending for a week should have been deleted")
	}
}

// Databases created before pending_since existed have it at 0; those rows must
// still expire, falling back to created_at.
func TestDeleteExpiredPendingFallsBackToCreatedAt(t *testing.T) {
	s := newTestStore(t)
	m := machineFor(t, s, "alice", "laptop", "k-alice-1")
	weekAgo := time.Now().Add(-7 * 24 * time.Hour).Unix()
	if _, err := s.db.Exec(`UPDATE machine SET created_at=?, pending_since=0 WHERE id=?`, weekAgo, m.ID); err != nil {
		t.Fatal(err)
	}

	n, err := s.DeleteExpiredPending(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d machine(s), want 1", n)
	}
}

// The icon set is closed: whatever a form submits, what lands in the database is
// always one of MachineIcons, so every renderer can look it up blindly.
func TestMachineIconIsAlwaysFromTheKnownSet(t *testing.T) {
	s := newTestStore(t)

	cases := map[string]string{
		"laptop":             "laptop",
		"server":             "server",
		"":                   DefaultMachineIcon, // no choice made
		"nas":                DefaultMachineIcon, // not in the set
		"<script>x</script>": DefaultMachineIcon,
	}
	i := 0
	for submitted, want := range cases {
		i++
		m := &Machine{OwnerUID: "alice", Name: "m", PublicKey: fmt.Sprintf("k-%d", i), Icon: submitted}
		if err := s.CreateMachine(m); err != nil {
			t.Fatal(err)
		}
		if m.Icon != want {
			t.Errorf("CreateMachine(%q): in-memory icon %q, want %q", submitted, m.Icon, want)
		}
		got, err := s.GetMachine(m.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Icon != want {
			t.Errorf("CreateMachine(%q): stored icon %q, want %q", submitted, got.Icon, want)
		}

		if err := s.UpdateMachineIdentity(m.ID, "m", got.PublicKey, submitted); err != nil {
			t.Fatal(err)
		}
		if got, err = s.GetMachine(m.ID); err != nil {
			t.Fatal(err)
		}
		if got.Icon != want {
			t.Errorf("UpdateMachineIdentity(%q): stored icon %q, want %q", submitted, got.Icon, want)
		}
	}
}

// A database written by a version without the icon column must migrate, and its
// existing machines must come back carrying the default icon rather than an
// empty string. Dropping the column reproduces that older shape.
func TestMachineIconMigratesExistingDatabase(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	old, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := machineFor(t, old, "alice", "laptop", "k-legacy")
	if _, err := old.db.Exec(`ALTER TABLE machine DROP COLUMN icon`); err != nil {
		t.Fatalf("simulate a pre-icon database: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("reopen (migration): %v", err)
	}
	defer s.Close()
	got, err := s.GetMachine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Icon != DefaultMachineIcon {
		t.Errorf("migrated machine icon %q, want %q", got.Icon, DefaultMachineIcon)
	}
}

// machine.last_seen is what the dormancy check reads, so it must record every
// handshake a hub reports, only ever move forward, and survive the peer leaving
// the hub's report.
func TestLastSeenFollowsReports(t *testing.T) {
	st := newTestStore(t)
	ep := &Endpoint{Name: "par", PublicKey: "k", HostPort: "h:51820", UploadToken: "t"}
	if err := st.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	m := &Machine{OwnerUID: "alice", Name: "laptop", PublicKey: "peer-key"}
	if err := st.CreateMachine(m); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetMachine(m.ID); !got.LastSeen.IsZero() {
		t.Fatalf("last seen = %v on a machine that never connected, want zero", got.LastSeen)
	}

	handshake := time.Now().Add(-time.Minute).Truncate(time.Second)
	report := func(peers []StatusPeer) {
		t.Helper()
		if err := st.ReplaceStatus(ep.ID, peers, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	report([]StatusPeer{{PublicKey: "peer-key", LastHandshake: handshake}})
	got, err := st.GetMachine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.Equal(handshake) {
		t.Errorf("last seen = %v, want %v", got.LastSeen, handshake)
	}

	// An older handshake (a hub that restarted, another endpoint lagging behind)
	// must not move it back.
	report([]StatusPeer{{PublicKey: "peer-key", LastHandshake: handshake.Add(-time.Hour)}})
	if got, _ = st.GetMachine(m.ID); !got.LastSeen.Equal(handshake) {
		t.Errorf("last seen = %v after an older report, want it kept at %v", got.LastSeen, handshake)
	}

	// The peer disappears from the hub entirely: the record stays.
	report(nil)
	if got, _ = st.GetMachine(m.ID); !got.LastSeen.Equal(handshake) {
		t.Errorf("last seen = %v once the hub dropped the peer, want it kept at %v", got.LastSeen, handshake)
	}
}

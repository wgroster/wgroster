package store

import (
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

package store

import (
	"testing"
	"time"
)

func TestMachineOwnerUIDsIsDistinct(t *testing.T) {
	s := newTestStore(t)
	machineFor(t, s, "alice", "laptop", "k-alice-1")
	machineFor(t, s, "alice", "phone", "k-alice-2")
	machineFor(t, s, "bob", "laptop", "k-bob-1")

	uids, err := s.MachineOwnerUIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) != 2 || uids[0] != "alice" || uids[1] != "bob" {
		t.Fatalf("MachineOwnerUIDs = %v, want [alice bob]", uids)
	}
}

func TestOwnerCheckAbsenceAccumulatesThenResets(t *testing.T) {
	s := newTestStore(t)
	now := time.Unix(1_700_000_000, 0)

	first, err := s.MarkOwnerAbsent("alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Misses != 1 || !first.AbsentSince.Equal(now) {
		t.Fatalf("first absence = %+v, want 1 miss since %v", first, now)
	}
	if first.Orphaned() {
		t.Error("a single absence must not read as orphaned")
	}

	later := now.Add(24 * time.Hour)
	second, err := s.MarkOwnerAbsent("alice", later)
	if err != nil {
		t.Fatal(err)
	}
	if second.Misses != 2 {
		t.Errorf("misses = %d, want 2", second.Misses)
	}
	// absent_since must keep pointing at the *first* absence, so the admin page
	// can say how long the account has been gone.
	if !second.AbsentSince.Equal(now) {
		t.Errorf("absent since %v, want the first absence %v", second.AbsentSince, now)
	}
	if !second.CheckedAt.Equal(later) {
		t.Errorf("checked at %v, want %v", second.CheckedAt, later)
	}

	// A re-created account recovers on its own: presence clears everything.
	if err := s.FlagOwnerOrphaned("alice", later); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkOwnerPresent("alice", later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c, err := s.OwnerCheck("alice")
	if err != nil {
		t.Fatal(err)
	}
	if c.Misses != 0 || !c.AbsentSince.IsZero() || c.Orphaned() {
		t.Errorf("after presence = %+v, want a cleared record", c)
	}
}

func TestOwnerCheckUnknownUserIsZero(t *testing.T) {
	s := newTestStore(t)
	c, err := s.OwnerCheck("nobody")
	if err != nil {
		t.Fatalf("OwnerCheck for an unrecorded user: %v", err)
	}
	if c.Misses != 0 || c.Orphaned() || !c.CheckedAt.IsZero() {
		t.Errorf("got %+v, want a zero value", c)
	}
}

func TestPruneOwnerChecksDropsOwnersWithoutMachines(t *testing.T) {
	s := newTestStore(t)
	m := machineFor(t, s, "alice", "laptop", "k-alice-1")
	machineFor(t, s, "bob", "laptop", "k-bob-1")
	now := time.Unix(1_700_000_000, 0)
	if _, err := s.MarkOwnerAbsent("alice", now); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkOwnerPresent("bob", now); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteMachine(m.ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneOwnerChecks()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
	checks, err := s.OwnerChecks()
	if err != nil {
		t.Fatal(err)
	}
	if _, gone := checks["alice"]; gone {
		t.Error("alice has no machine left; her check record should be gone")
	}
	if _, kept := checks["bob"]; !kept {
		t.Error("bob still owns a machine; his check record must be kept")
	}
}

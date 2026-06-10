package store

import (
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestDuplicateAddressRejected(t *testing.T) {
	st := newTestStore(t)

	m1 := &Machine{OwnerUID: "alice", Name: "a", PublicKey: "k1"}
	m2 := &Machine{OwnerUID: "bob", Name: "b", PublicKey: "k2"}
	if err := st.CreateMachine(m1); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateMachine(m2); err != nil {
		t.Fatal(err)
	}

	if err := st.ApproveMachine(m1.ID, "10.0.0.5", nil, "admin"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	// The unique partial index must reject a second machine on the same address.
	if err := st.ApproveMachine(m2.ID, "10.0.0.5", nil, "admin"); err == nil {
		t.Fatal("expected duplicate address to be rejected, got nil")
	}

	// Re-approving the same machine with its own address must still work.
	if err := st.ApproveMachine(m1.ID, "10.0.0.5", nil, "admin"); err != nil {
		t.Fatalf("re-approve same machine/address: %v", err)
	}
}

func TestOwnerName(t *testing.T) {
	st := newTestStore(t)

	m := &Machine{OwnerUID: "lionel", OwnerName: "Lionel Porcheron", Name: "laptop", PublicKey: "k1"}
	if err := st.CreateMachine(m); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetMachine(m.ID)
	if got.OwnerName != "Lionel Porcheron" {
		t.Errorf("owner_name not persisted: %q", got.OwnerName)
	}
	if got.OwnerDisplay() != "Lionel Porcheron" {
		t.Errorf("OwnerDisplay = %q", got.OwnerDisplay())
	}

	// Empty owner_name falls back to uid.
	m2 := &Machine{OwnerUID: "bob", Name: "desk", PublicKey: "k2"}
	st.CreateMachine(m2)
	got2, _ := st.GetMachine(m2.ID)
	if got2.OwnerDisplay() != "bob" {
		t.Errorf("fallback display = %q, want bob", got2.OwnerDisplay())
	}

	// UpdateOwnerName refreshes (and would backfill) all of a user's machines.
	if err := st.UpdateOwnerName("bob", "Bob Smith"); err != nil {
		t.Fatal(err)
	}
	got2, _ = st.GetMachine(m2.ID)
	if got2.OwnerName != "Bob Smith" {
		t.Errorf("UpdateOwnerName failed: %q", got2.OwnerName)
	}
}

func TestStatusHistoryThroughput(t *testing.T) {
	st := newTestStore(t)
	ep := &Endpoint{Name: "e1", PublicKey: "k", HostPort: "h:1", UploadToken: "t"}
	if err := st.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}

	t1 := time.Unix(1_700_000_000, 0)
	t2 := t1.Add(10 * time.Second) // dt = 10s
	if err := st.ReplaceStatus(ep.ID, []StatusPeer{{PublicKey: "pk", RX: 1000, TX: 2000}}, t1); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceStatus(ep.ID, []StatusPeer{{PublicKey: "pk", RX: 6000, TX: 2000}}, t2); err != nil {
		t.Fatal(err)
	}

	rates, err := st.EndpointThroughput(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	// rx delta 5000 over 10s = 500 B/s; tx unchanged = 0.
	if got := rates["pk"]; got[0] != 500 || got[1] != 0 {
		t.Errorf("throughput = %v, want [500 0]", got)
	}

	series, err := st.EndpointSeries(ep.ID, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || series[0] != 500 {
		t.Errorf("series = %v, want [500]", series)
	}
}

func TestPendingMachinesShareEmptyAddress(t *testing.T) {
	st := newTestStore(t)
	// Several pending machines all have an empty address; the partial index must
	// not treat those as duplicates.
	for i, pk := range []string{"k1", "k2", "k3"} {
		m := &Machine{OwnerUID: "alice", Name: string(rune('a' + i)), PublicKey: pk}
		if err := st.CreateMachine(m); err != nil {
			t.Fatalf("create %s: %v", pk, err)
		}
	}
}

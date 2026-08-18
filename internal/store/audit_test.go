package store

import (
	"testing"
	"time"
)

func TestDeleteAuditBefore(t *testing.T) {
	st := newTestStore(t)
	for _, action := range []string{"a", "b", "c"} {
		if err := st.AddAudit("admin", action, "target"); err != nil {
			t.Fatal(err)
		}
	}
	// Entries are stamped with time.Now(), so a past cutoff keeps everything.
	n, err := st.DeleteAuditBefore(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("deleted %d entries with a past cutoff, want 0", n)
	}
	if entries, err := st.ListAudit(10); err != nil || len(entries) != 3 {
		t.Fatalf("ListAudit = %d entries, err %v", len(entries), err)
	}

	n, err = st.DeleteAuditBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("deleted %d entries, want 3", n)
	}
	if entries, err := st.ListAudit(10); err != nil || len(entries) != 0 {
		t.Fatalf("ListAudit after pruning = %d entries, err %v", len(entries), err)
	}
}

func TestListAuditRespectsLimit(t *testing.T) {
	st := newTestStore(t)
	for i := 0; i < 5; i++ {
		if err := st.AddAudit("admin", "action", "target"); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := st.ListAudit(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	// Newest first.
	if entries[0].ID < entries[1].ID {
		t.Errorf("entries are not newest-first: %d then %d", entries[0].ID, entries[1].ID)
	}
}

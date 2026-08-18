package web

import (
	"testing"
	"time"

	"github.com/wgroster/wgroster/internal/store"
)

// staleUIDs decides which directory profiles are re-read from LDAP. It runs on
// every status poll, and no integration test reaches it (they have no LDAP), so
// pin the TTL logic here.
func TestStaleUIDs(t *testing.T) {
	now := time.Now()
	cached := map[string]store.ProfileMeta{
		"fresh":       {DisplayName: "Fresh", FetchedAt: now.Add(-time.Hour)},
		"stale":       {DisplayName: "Stale", FetchedAt: now.Add(-profileTTL - time.Minute)},
		"never":       {}, // cached with a zero fetched_at: never actually fetched
		"empty-fresh": {FetchedAt: now.Add(-time.Minute)},
	}

	got := staleUIDs([]string{"fresh", "stale", "never", "empty-fresh", "unknown", ""}, cached, now)

	want := []string{"stale", "never", "unknown"}
	if len(got) != len(want) {
		t.Fatalf("staleUIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("staleUIDs = %v, want %v", got, want)
			break
		}
	}
}

func TestStaleUIDsEmptyInputs(t *testing.T) {
	if got := staleUIDs(nil, nil, time.Now()); len(got) != 0 {
		t.Errorf("staleUIDs(nil, nil) = %v, want none", got)
	}
	// With no cache at all every uid is stale, which is what a first load wants.
	got := staleUIDs([]string{"a", "b"}, map[string]store.ProfileMeta{}, time.Now())
	if len(got) != 2 {
		t.Errorf("staleUIDs with an empty cache = %v, want both", got)
	}
}

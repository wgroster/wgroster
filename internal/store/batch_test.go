package store

import (
	"strings"
	"testing"
	"time"
)

// The listing pages rely on these batch queries returning exactly what the
// per-row queries they replaced returned.
func TestBatchQueriesMatchPerRowQueries(t *testing.T) {
	st := newTestStore(t)

	par := &Endpoint{Name: "par", PublicKey: "ep1", HostPort: "par:1", UploadToken: "t1"}
	ams := &Endpoint{Name: "ams", PublicKey: "ep2", HostPort: "ams:1", UploadToken: "t2"}
	for _, e := range []*Endpoint{par, ams} {
		if err := st.CreateEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}

	laptop := &Machine{OwnerUID: "alice", Name: "laptop", PublicKey: "k-laptop"}
	phone := &Machine{OwnerUID: "alice", Name: "phone", PublicKey: "k-phone"}
	desktop := &Machine{OwnerUID: "bob", Name: "desktop", PublicKey: "k-desktop"}
	pending := &Machine{OwnerUID: "bob", Name: "new", PublicKey: "k-new"}
	for _, m := range []*Machine{laptop, phone, desktop, pending} {
		if err := st.CreateMachine(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.ApproveMachine(laptop.ID, "10.0.0.5", []int64{par.ID, ams.ID}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.ApproveMachine(phone.ID, "10.0.0.6", []int64{par.ID}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := st.ApproveMachine(desktop.ID, "10.0.0.7", []int64{ams.ID}, "admin"); err != nil {
		t.Fatal(err)
	}

	links, err := st.EndpointLinks("")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*Machine{laptop, phone, desktop, pending} {
		want, err := st.EndpointIDsForMachine(m.ID)
		if err != nil {
			t.Fatal(err)
		}
		got := links[m.ID]
		if len(got) != len(want) {
			t.Fatalf("EndpointLinks[%s] = %v, want %v", m.Name, got, want)
		}
		seen := map[int64]bool{}
		for _, id := range got {
			seen[id] = true
		}
		for _, id := range want {
			if !seen[id] {
				t.Errorf("EndpointLinks[%s] = %v, missing %d", m.Name, got, id)
			}
		}
	}

	// Scoping to an owner leaves the other users' machines out.
	scoped, err := st.EndpointLinks("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 2 || len(scoped[laptop.ID]) != 2 || len(scoped[phone.ID]) != 1 {
		t.Errorf("EndpointLinks(alice) = %v", scoped)
	}
	if _, ok := scoped[desktop.ID]; ok {
		t.Error("EndpointLinks(alice) leaked bob's machine")
	}

	// Two endpoints report the same peer with different handshakes: the batch
	// query must surface the most recent one, like PeersByKey + max did.
	now := time.Now().Truncate(time.Second)
	older, newer := now.Add(-10*time.Minute), now.Add(-1*time.Minute)
	if err := st.ReplaceStatus(par.ID, []StatusPeer{
		{PublicKey: "k-laptop", LastHandshake: older},
		{PublicKey: "k-phone", LastHandshake: now},
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceStatus(ams.ID, []StatusPeer{
		{PublicKey: "k-laptop", LastHandshake: newer},
		{PublicKey: "k-desktop", LastHandshake: now},
	}, now); err != nil {
		t.Fatal(err)
	}

	hs, err := st.LastHandshakeByKey("")
	if err != nil {
		t.Fatal(err)
	}
	if !hs["k-laptop"].Equal(newer) {
		t.Errorf("LastHandshakeByKey[k-laptop] = %s, want %s", hs["k-laptop"], newer)
	}
	if len(hs) != 3 {
		t.Errorf("LastHandshakeByKey returned %d keys, want 3", len(hs))
	}
	if _, ok := hs["k-new"]; ok {
		t.Error("a never-reported peer must be absent, not zero")
	}

	scopedHS, err := st.LastHandshakeByKey("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopedHS) != 1 || !scopedHS["k-desktop"].Equal(now) {
		t.Errorf("LastHandshakeByKey(bob) = %v", scopedHS)
	}
}

func TestAllUserProfileMetas(t *testing.T) {
	st := newTestStore(t)
	if err := st.UpsertUserProfile("alice", "Alice Example", []byte("jpegdata"), "image/jpeg"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertUserProfile("bob", "Bob Example", nil, ""); err != nil {
		t.Fatal(err)
	}

	metas, err := st.AllUserProfileMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("got %d profiles, want 2", len(metas))
	}
	if !metas["alice"].HasPhoto || metas["alice"].DisplayName != "Alice Example" {
		t.Errorf("alice = %+v", metas["alice"])
	}
	if metas["bob"].HasPhoto {
		t.Errorf("bob = %+v, want HasPhoto false", metas["bob"])
	}
	// A missing uid yields the zero value, which the pages treat as "no profile".
	if metas["ghost"].DisplayName != "" || metas["ghost"].HasPhoto {
		t.Errorf("ghost = %+v, want zero", metas["ghost"])
	}

	// Each entry must agree with the single-row query it replaces.
	for uid, m := range metas {
		name, hasPhoto, _, found, err := st.UserProfileMeta(uid)
		if err != nil || !found {
			t.Fatalf("UserProfileMeta(%s): found %v, err %v", uid, found, err)
		}
		if name != m.DisplayName || hasPhoto != m.HasPhoto {
			t.Errorf("%s: batch %+v vs single (%q, %v)", uid, m, name, hasPhoto)
		}
	}
}

// TestHotQueriesUseIndexes pins the query plans of the lookups that run on every
// dashboard poll and every peer drawer. Without the covering indexes SQLite
// falls back to scanning status_peer / status_history in full, which is invisible
// on a fresh database and painful on a real fleet.
func TestHotQueriesUseIndexes(t *testing.T) {
	st := newTestStore(t)
	cases := []struct {
		name  string
		query string
		index string
	}{
		{
			name:  "peer by public key",
			query: `SELECT endpoint_id FROM status_peer WHERE public_key='x'`,
			index: "idx_status_peer_key",
		},
		{
			name:  "peer history series",
			query: `SELECT report_ts FROM status_history WHERE endpoint_id=1 AND public_key='x' ORDER BY report_ts DESC LIMIT 60`,
			index: "idx_status_history_peer",
		},
		{
			name:  "machines by owner",
			query: `SELECT id FROM machine WHERE owner_uid='x'`,
			index: "idx_machine_owner",
		},
		{
			// This one runs inside every status upload, not on a read path.
			name:  "history retention trim",
			query: `DELETE FROM status_history WHERE report_ts < 0`,
			index: "idx_status_history_ts",
		},
		{
			name:  "audit retention prune",
			query: `DELETE FROM audit_log WHERE ts < 0`,
			index: "idx_audit_ts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := st.db.Query("EXPLAIN QUERY PLAN " + tc.query)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan string
			for rows.Next() {
				var id, parent, notUsed int
				var detail string
				if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
					t.Fatal(err)
				}
				plan += detail + "\n"
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan, tc.index) {
				t.Errorf("query plan does not use %s:\n%s", tc.index, plan)
			}
		})
	}
}

// The trim that runs inside every status upload must actually drop samples past
// the retention window while keeping the recent ones.
func TestStatusHistoryRetention(t *testing.T) {
	st := newTestStore(t)
	ep := &Endpoint{Name: "par", PublicKey: "ep", HostPort: "par:1", UploadToken: "t"}
	if err := st.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Truncate(time.Second)
	old := now.Add(-historyRetention - time.Hour)
	recent := now.Add(-time.Hour)
	for _, ts := range []time.Time{old, recent, now} {
		if err := st.ReplaceStatus(ep.ID, []StatusPeer{
			{PublicKey: "k", LastHandshake: ts, RX: 1, TX: 1},
		}, ts); err != nil {
			t.Fatal(err)
		}
	}

	samples, err := st.PeerSeries(ep.ID, "k", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("got %d samples, want the two inside the retention window", len(samples))
	}
	// Oldest first, and the out-of-window sample is gone.
	if !samples[0].TS.Equal(recent) || !samples[1].TS.Equal(now) {
		t.Errorf("samples = %v / %v, want %v / %v", samples[0].TS, samples[1].TS, recent, now)
	}

	first, found, err := st.PeerFirstSeen(ep.ID, "k")
	if err != nil || !found {
		t.Fatalf("PeerFirstSeen: found %v, err %v", found, err)
	}
	if !first.Equal(recent) {
		t.Errorf("first seen = %s, want %s (the trimmed sample must not linger)", first, recent)
	}
}

package store

import (
	"testing"
	"time"
)

// TrafficByKey feeds the machines list: every peer of an endpoint in one query,
// with the current rates and a curve, derived from the stored counters.
func TestTrafficByKey(t *testing.T) {
	st := newTestStore(t)
	ep := &Endpoint{Name: "par", PublicKey: "k", HostPort: "h:51820", UploadToken: "t"}
	if err := st.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}

	// Three reports 10s apart. "busy" transfers 100 B/s down and 50 B/s up in
	// the last interval; "idle" does not move; "reset" has its counters go
	// backwards, as after a hub restart.
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	reports := []struct {
		at    time.Time
		peers []StatusPeer
	}{
		{base, []StatusPeer{{PublicKey: "busy", RX: 0, TX: 0}, {PublicKey: "idle", RX: 7, TX: 7}, {PublicKey: "reset", RX: 5000, TX: 5000}}},
		{base.Add(10 * time.Second), []StatusPeer{{PublicKey: "busy", RX: 500, TX: 250}, {PublicKey: "idle", RX: 7, TX: 7}, {PublicKey: "reset", RX: 6000, TX: 6000}}},
		{base.Add(20 * time.Second), []StatusPeer{{PublicKey: "busy", RX: 1500, TX: 750}, {PublicKey: "idle", RX: 7, TX: 7}, {PublicKey: "reset", RX: 10, TX: 10}}},
	}
	for _, r := range reports {
		if err := st.ReplaceStatus(ep.ID, r.peers, r.at); err != nil {
			t.Fatal(err)
		}
	}

	traffic, err := st.TrafficByKey(ep.ID, 24)
	if err != nil {
		t.Fatal(err)
	}
	busy := traffic["busy"]
	if busy.RxRate != 100 || busy.TxRate != 50 {
		t.Errorf("busy rates = %d/%d B/s, want 100/50", busy.RxRate, busy.TxRate)
	}
	if len(busy.Series) != 2 {
		t.Errorf("busy series = %v, want one point per interval", busy.Series)
	} else if busy.Series[0] != 75 || busy.Series[1] != 150 {
		t.Errorf("busy series = %v, want [75 150] (rx+tx per interval)", busy.Series)
	}
	if idle := traffic["idle"]; idle.RxRate != 0 || idle.TxRate != 0 || len(idle.Series) != 2 {
		t.Errorf("idle = %+v, want a flat two-point series", idle)
	}
	if reset := traffic["reset"]; reset.RxRate != 0 || reset.TxRate != 0 {
		t.Errorf("reset = %+v, want counters going backwards to read as 0, not negative", reset)
	}

	// Only the requested window is scanned: one interval means one point.
	if got, err := st.TrafficByKey(ep.ID, 1); err != nil {
		t.Fatal(err)
	} else if len(got["busy"].Series) != 1 {
		t.Errorf("windowed series = %v, want a single point", got["busy"].Series)
	}

	// A peer nobody reported has no entry at all.
	if _, ok := traffic["ghost"]; ok {
		t.Error("an unreported peer must be absent from the map")
	}
}

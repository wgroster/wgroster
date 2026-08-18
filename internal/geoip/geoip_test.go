package geoip

import (
	"path/filepath"
	"testing"
)

// The peer drawer calls into this package unconditionally, so the disabled and
// nil paths must stay allocation-free and panic-free.
func TestDisabledLookupIsSafe(t *testing.T) {
	l, err := New("", "")
	if err != nil {
		t.Fatalf("New with no database: %v", err)
	}
	if l.Enabled() {
		t.Error("Enabled() = true with no database configured")
	}
	if got := l.Lookup("203.0.113.5"); !got.Empty() {
		t.Errorf("Lookup = %+v, want empty", got)
	}
	l.Close()

	var nilLookup *Lookup
	if nilLookup.Enabled() {
		t.Error("nil Lookup reports Enabled()")
	}
	if got := nilLookup.Lookup("203.0.113.5"); !got.Empty() {
		t.Errorf("nil Lookup = %+v, want empty", got)
	}
	nilLookup.Close() // must not panic
}

func TestMissingDatabaseIsAnError(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "absent.mmdb"), ""); err == nil {
		t.Fatal("expected an error for a missing city database")
	}
	if _, err := New("", filepath.Join(t.TempDir(), "absent.mmdb")); err == nil {
		t.Fatal("expected an error for a missing ASN database")
	}
}

func TestResultEmpty(t *testing.T) {
	cases := []struct {
		r    Result
		want bool
	}{
		{Result{}, true},
		{Result{Country: "FR"}, false},
		{Result{City: "Toulouse"}, false},
		{Result{ASN: "AS3215"}, false},
		{Result{Org: "Orange"}, false},
	}
	for _, tc := range cases {
		if got := tc.r.Empty(); got != tc.want {
			t.Errorf("Empty(%+v) = %v, want %v", tc.r, got, tc.want)
		}
	}
}

func TestInvalidIPIsIgnored(t *testing.T) {
	l, _ := New("", "")
	for _, ip := range []string{"", "not-an-ip", "203.0.113.5:51820"} {
		if got := l.Lookup(ip); !got.Empty() {
			t.Errorf("Lookup(%q) = %+v, want empty", ip, got)
		}
	}
}

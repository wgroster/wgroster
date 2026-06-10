package web

import (
	"strings"
	"testing"
	"time"
)

func TestSince(t *testing.T) {
	if got := since(time.Time{}); got != "never" {
		t.Errorf("since(zero) = %q, want never", got)
	}

	s := since(time.Now().Add(-(2*time.Hour + 3*time.Minute + 30*time.Second)))
	for _, want := range []string{"2 hours", "3 minutes", "30 second", "ago"} {
		if !strings.Contains(s, want) {
			t.Errorf("since(...) = %q, missing %q", s, want)
		}
	}
	if strings.Contains(s, "day") {
		t.Errorf("since(...) = %q, should not mention days", s)
	}

	// Singular vs plural.
	if got := since(time.Now().Add(-1 * time.Minute)); !strings.HasPrefix(got, "1 minute") {
		t.Errorf("since(1m) = %q, want '1 minute...'", got)
	}
}

func TestExact(t *testing.T) {
	if got := exact(time.Time{}); got != "" {
		t.Errorf("exact(zero) = %q, want empty", got)
	}
	got := exact(time.Date(2026, 5, 29, 8, 1, 21, 0, time.UTC))
	if !strings.Contains(got, "May 29") || !strings.Contains(got, "2026") || !strings.Contains(got, "08:01:21") {
		t.Errorf("exact(...) = %q", got)
	}
}

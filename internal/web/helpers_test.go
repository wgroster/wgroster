package web

import "testing"

func TestAllowedCovers(t *testing.T) {
	cases := []struct {
		list, addr string
		want       bool
	}{
		{"10.0.0.5/32", "10.0.0.5", true},
		{"10.0.0.5/32, fd00::5/128", "10.0.0.5", true},
		{"10.0.0.0/24", "10.0.0.5", true}, // broader range still covers
		{"10.0.0.99/32", "10.0.0.5", false},
		{"", "10.0.0.5", false},
		{"10.0.0.5/32", "not-an-ip", true}, // unjudgeable -> no false alarm
	}
	for _, c := range cases {
		if got := allowedCovers(c.list, c.addr); got != c.want {
			t.Errorf("allowedCovers(%q, %q) = %v, want %v", c.list, c.addr, got, c.want)
		}
	}
}

package wg

import "testing"

func TestParseAllowedIPs(t *testing.T) {
	tests := []struct {
		list string
		want []string
		ok   bool
	}{
		{"10.0.0.0/8", []string{"10.0.0.0/8"}, true},
		{" 10.0.0.0/8 , 192.168.1.0/24 ", []string{"10.0.0.0/8", "192.168.1.0/24"}, true},
		{"192.168.1.5", []string{"192.168.1.5/32"}, true},
		{"fd00::/8", []string{"fd00::/8"}, true},
		{"2001:db8::1", []string{"2001:db8::1/128"}, true},
		{"10.0.0.1/8", []string{"10.0.0.0/8"}, true}, // host bits masked, as WireGuard does
		{"", nil, true},
		{"10.0.0.0/33", nil, false},
		{"10.0.0.0/8, nope", nil, false},
		{"10.0.0.256", nil, false},
		{"10.0.0.0-10.0.0.255", nil, false},
	}
	for _, tc := range tests {
		got, err := ParseAllowedIPs(tc.list)
		if (err == nil) != tc.ok {
			t.Errorf("ParseAllowedIPs(%q) error = %v, want ok=%v", tc.list, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("ParseAllowedIPs(%q) = %v, want %v", tc.list, got, tc.want)
			continue
		}
		for i := range got {
			if got[i].String() != tc.want[i] {
				t.Errorf("ParseAllowedIPs(%q)[%d] = %s, want %s", tc.list, i, got[i], tc.want[i])
			}
		}
	}
}

func TestAllowedIPsOrDefaultsToEverything(t *testing.T) {
	got, err := AllowedIPsOr("  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != DefaultAllowedIPs {
		t.Errorf("AllowedIPsOr(\"\") = %v, want %s", got, DefaultAllowedIPs)
	}
}

func TestOverlap(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"two default routes", "0.0.0.0/0", "0.0.0.0/0", true},
		{"default route swallows everything", "0.0.0.0/0", "192.168.1.0/24", true},
		{"nested", "10.0.0.0/8", "10.1.2.0/24", true},
		{"identical", "10.0.0.0/8", "10.0.0.0/8", true},
		{"host inside a network", "10.0.0.0/8", "10.0.0.5", true},
		{"disjoint", "10.0.0.0/8", "192.168.1.0/24", false},
		{"adjacent", "10.0.0.0/25", "10.0.0.128/25", false},
		{"different families", "0.0.0.0/0", "fd00::/8", false},
		{"one list among several", "10.0.0.0/8, 172.16.0.0/12", "192.168.0.0/16, 172.16.5.0/24", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseAllowedIPs(tc.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ParseAllowedIPs(tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, got := Overlap(a, b); got != tc.want {
				t.Errorf("Overlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

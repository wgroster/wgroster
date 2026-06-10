package ipam

import "testing"

func TestNextFree(t *testing.T) {
	p, err := New("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// Network address (.0) is skipped; first free is .1.
	got, err := p.NextFree(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.1" {
		t.Errorf("got %q, want 10.0.0.1", got)
	}

	got, err = p.NextFree([]string{"10.0.0.1", "10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.3" {
		t.Errorf("got %q, want 10.0.0.3", got)
	}
}

func TestNextFreeSkipsBroadcast(t *testing.T) {
	// A /30 has usable hosts .1 and .2; .0 is the network and .3 the broadcast.
	p, err := New("10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	// With .1 and .2 taken, the pool is exhausted — .3 (broadcast) is not handed
	// out.
	if _, err := p.NextFree([]string{"10.0.0.1", "10.0.0.2"}); err == nil {
		t.Error("NextFree returned an address; expected pool exhausted (broadcast must be skipped)")
	}
}

func TestValidate(t *testing.T) {
	p, _ := New("10.0.0.0/24")
	cases := []struct {
		addr string
		used []string
		ok   bool
	}{
		{"10.0.0.5", nil, true},
		{"10.0.0.0", nil, false},                  // network address
		{"10.0.0.255", nil, false},                // broadcast address
		{"10.1.0.5", nil, false},                  // outside range
		{"not-an-ip", nil, false},                 // invalid
		{"10.0.0.5", []string{"10.0.0.5"}, false}, // already used
	}
	for _, c := range cases {
		err := p.Validate(c.addr, c.used)
		if (err == nil) != c.ok {
			t.Errorf("Validate(%q, %v) error=%v, want ok=%v", c.addr, c.used, err, c.ok)
		}
	}
}

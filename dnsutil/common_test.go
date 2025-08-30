package dnsutil

import "testing"

func TestCommon(t *testing.T) {
	s1 := "www.miek.nl."
	s2 := "miek.nl."
	s3 := "www.bla.nl."
	s4 := "nl.www.bla."
	s5 := "nl."
	s6 := "miek.nl."

	if Common(s1, s2) != 2 {
		t.Errorf("%s with %s should be %d", s1, s2, 2)
	}
	if Common(s1, s3) != 1 {
		t.Errorf("%s with %s should be %d", s1, s3, 1)
	}
	if Common(s3, s4) != 0 {
		t.Errorf("%s with %s should be %d", s3, s4, 0)
	}
	// Non qualified tests
	if Common(s1, s5) != 1 {
		t.Errorf("%s with %s should be %d", s1, s5, 1)
	}
	if Common(s1, s6) != 2 {
		t.Errorf("%s with %s should be %d", s1, s5, 2)
	}

	if Common(s1, ".") != 0 {
		t.Errorf("%s with %s should be %d", s1, s5, 0)
	}
	if x := Common(".", "."); x != 0 {
		t.Errorf("%s with %s should be %d, got %d", ".", ".", 0, x)
	}
	if Common("test.com.", "TEST.COM.") != 2 {
		t.Errorf("test.com. and TEST.COM. should be an exact match")
	}
}

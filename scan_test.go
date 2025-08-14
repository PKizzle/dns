package dns

import "testing"

func TestParseOpenEscape(t *testing.T) {
	if _, err := New("example.net IN CNAME example.net."); err != nil {
		t.Fatalf("expected no error, but got: %s", err)
	}
	if _, err := New("example.net IN CNAME example.org\\"); err == nil {
		t.Fatalf("expected an error, but got none")
	}
}

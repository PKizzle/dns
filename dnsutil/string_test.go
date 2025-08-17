package dnsutil

import "testing"

func TestToString(t *testing.T) {
	if x := RcodeToString(5); x != "REFUSED" {
		t.Errorf("expected %s, got %s", "REFUSED", x)
	}
	if x := RcodeToString(55); x != "RCODE55" {
		t.Errorf("expected %s, got %s", "RCODE55", x)
	}
	if x := OpcodeToString(0); x != "QUERY" {
		t.Errorf("expected %s, got %s", "QUERY", x)
	}
	if x := OpcodeToString(12); x != "OPCODE12" {
		t.Errorf("expected %s, got %s", "OPCODE12", x)
	}
	if x := TypeToString(1); x != "A" {
		t.Errorf("expected %s, got %s", "A", x)
	}
	if x := ClassToString(1); x != "IN" {
		t.Errorf("expected %s, got %s", "IN", x)
	}
}

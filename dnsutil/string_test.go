package dnsutil

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

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
	if x := CodeToString(10); x != "COOKIE" {
		t.Errorf("expected %s, got %s", "COOKIE", x)
	}
}

func TestStringToType(t *testing.T) {
	tests := map[string]struct {
		Type   uint16
		ErrNil bool
	}{
		"A":                     {dns.TypeA, true},
		"AAAA":                  {dns.TypeAAAA, true},
		"a":                     {dns.TypeA, true},
		"banana":                {0, false},
		"type1":                 {dns.TypeA, true},
		"typex":                 {0, false},
		"type100000":            {0, false},
		TypeToString(dns.TypeA): {dns.TypeA, true},
		TypeToString(60000):     {60000, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := StringToType(name)
			if !tc.ErrNil && err == nil {
				t.Errorf("expected error, got nil")
			}
			if tc.ErrNil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				} else {
					if got != tc.Type {
						t.Errorf("expected %v, got %v", tc.Type, got)
					}
				}
			}
		})
	}
}

func TestStringToRCode(t *testing.T) {
	tests := map[string]struct {
		Rcode  uint16
		ErrNil bool
	}{
		"REFUSED":                         {dns.RcodeRefused, true},
		"refused":                         {dns.RcodeRefused, true},
		"banana":                          {0, false},
		"rcode5":                          {dns.RcodeRefused, true},
		"RCODE55":                         {55, true},
		"rcodex":                          {0, false},
		"rcode100000":                     {0, false},
		RcodeToString(dns.RcodeBadCookie): {dns.RcodeBadCookie, true},
		RcodeToString(55):                 {55, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := StringToRcode(name)
			if !tc.ErrNil && err == nil {
				t.Errorf("expected error, got nil")
			}
			if tc.ErrNil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				} else {
					if got != tc.Rcode {
						t.Errorf("expected %v, got %v", tc.Rcode, got)
					}
				}
			}
		})
	}
}

func TestStringToClass(t *testing.T) {
	tests := map[string]struct {
		Class  uint16
		ErrNil bool
	}{
		"IN":                          {dns.ClassINET, true},
		"in":                          {dns.ClassINET, true},
		"banana":                      {0, false},
		"CLass1":                      {dns.ClassINET, true},
		"classx":                      {0, false},
		"class100000":                 {0, false},
		ClassToString(dns.ClassCHAOS): {dns.ClassCHAOS, true},
		ClassToString(200):            {200, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := StringToClass(name)
			if !tc.ErrNil && err == nil {
				t.Errorf("expected error, got nil")
			}
			if tc.ErrNil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				} else {
					if got != tc.Class {
						t.Errorf("expected %v, got %v", tc.Class, got)
					}
				}
			}
		})
	}
}

func TestStringToOpcode(t *testing.T) {
	tests := map[string]struct {
		Opcode uint8
		ErrNil bool
	}{
		"QUERY":                            {dns.OpcodeQuery, true},
		"status":                           {dns.OpcodeStatus, true},
		"banana":                           {0, false},
		"opcode0":                          {dns.OpcodeQuery, true},
		"opcodex":                          {0, false},
		"opcode300":                        {0, false},
		OpcodeToString(dns.OpcodeStateful): {dns.OpcodeStateful, true},
		OpcodeToString(20):                 {20, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := StringToOpcode(name)
			if !tc.ErrNil && err == nil {
				t.Errorf("expected error, got nil")
			}
			if tc.ErrNil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				} else {
					if got != tc.Opcode {
						t.Errorf("expected %v, got %v", tc.Opcode, got)
					}
				}
			}
		})
	}
}

func TestStringToCode(t *testing.T) {
	tests := map[string]struct {
		Code   uint16
		ErrNil bool
	}{
		"COOKIE":                       {dns.CodeCOOKIE, true},
		"cookie":                       {dns.CodeCOOKIE, true},
		"banana":                       {0, false},
		"code10":                       {dns.CodeCOOKIE, true},
		"codex":                        {0, false},
		"code100000":                   {0, false},
		CodeToString(dns.CodeLOCALEND): {dns.CodeLOCALEND, true},
		CodeToString(200):              {200, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := StringToCode(name)
			if !tc.ErrNil && err == nil {
				t.Errorf("expected error, got nil")
			}
			if tc.ErrNil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				} else {
					if got != tc.Code {
						t.Errorf("expected %v, got %v", tc.Code, got)
					}
				}
			}
		})
	}
}

func ExampleTypeToString() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	fmt.Println(TypeToString(dns.RRToType(rr)))
	// Output: MX
}

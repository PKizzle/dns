package dnsutil

import (
	"fmt"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
)

// TypeToString converts the type to the text presentation, or to "TYPE"+value if the type is unknown.
// Also see [ClassToString], [RcodeToString], [OpcodeToString], [CodeToString] for similar functions.
func TypeToString(t uint16) string {
	if t1, ok := dns.TypeToString[t]; ok {
		return t1
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// RcodeToString converts the code to the text presentation, or to "RCODE"+value if the rcode is unknown.
// Also see [ClassToString], [TypeToString], [OpcodeToString], [CodeToString] for similar functions.
func RcodeToString(r uint16) string {
	if r1, ok := dns.RcodeToString[r]; ok {
		return r1
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// ClassToString converts the class to the text presentation, or to "CLASS"+value if the class is unknown.
// Also see [RcodeToString], [TypeToString], [OpcodeToString], [CodeToString] for similar functions.
func ClassToString(c uint16) string {
	if c1, ok := dns.ClassToString[c]; ok {
		return c1
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// OpcodeToString converts the opcode to the text presentation, or to "OPCODE"+value if the opcode is unknown.
// Also see [RcodeToString], [TypeToString], [ClassToString], [CodeToString] for similar functions.
func OpcodeToString(o uint8) string {
	if o1, ok := dns.OpcodeToString[o]; ok {
		return o1
	}
	return "OPCODE" + strconv.Itoa(int(o))
}

// CodeToString converts the ENDS0 code to the text presentation, or to "CODE"+value if the code is unknown.
// Also see [RcodeToString], [TypeToString], [ClassToString], [OpcodeToString] for similar functions.
func CodeToString(c uint16) string {
	if c1, ok := dns.CodeToString[c]; ok {
		return c1
	}
	return "CODE" + strconv.Itoa(int(c))
}

// StringToType converts the text presentation or "TYPE"+value to a type.
// Inverse of [TypeToString].
func StringToType(s string) (uint16, error) {
	s2 := strings.ToUpper(s)
	if t1, ok := dns.StringToType[s2]; ok {
		return t1, nil
	}
	t2, ok := strings.CutPrefix(s2, "TYPE")
	if ok {
		t3, err := strconv.ParseUint(t2, 10, 16)
		if err == nil {
			return uint16(t3), nil
		}
	}
	return uint16(0), fmt.Errorf("invalid type %q", s)
}

// StringToRcode converts the text presentation or "RCODE"+value to a code.
// Inverse of [RcodeToString].
func StringToRcode(s string) (uint16, error) {
	s2 := strings.ToUpper(s)
	if r1, ok := dns.StringToRcode[s2]; ok {
		return r1, nil
	}
	r2, ok := strings.CutPrefix(s2, "RCODE")
	if ok {
		r3, err := strconv.ParseUint(r2, 10, 16)
		if err == nil {
			return uint16(r3), nil
		}
	}
	return uint16(0), fmt.Errorf("invalid rcode %q", s)
}

// StringToClass converts the text presentation or "CLASS"+value to a class.
// Inverse of [ClassToString].
func StringToClass(s string) (uint16, error) {
	s2 := strings.ToUpper(s)
	if c1, ok := dns.StringToClass[s2]; ok {
		return c1, nil
	}
	c2, ok := strings.CutPrefix(s2, "CLASS")
	if ok {
		c3, err := strconv.ParseUint(c2, 10, 16)
		if err == nil {
			return uint16(c3), nil
		}
	}
	return uint16(0), fmt.Errorf("invalid class %q", s)
}

// StringToOpcode converts the text representation or "OPCODE"+value to an opcode
// Inverse of [OpcodeToString].
func StringToOpcode(s string) (uint8, error) {
	s2 := strings.ToUpper(s)
	if o1, ok := dns.StringToOpcode[s2]; ok {
		return o1, nil
	}
	o2, ok := strings.CutPrefix(s2, "OPCODE")
	if ok {
		o3, err := strconv.ParseUint(o2, 10, 8)
		if err == nil {
			return uint8(o3), nil
		}
	}
	return uint8(0), fmt.Errorf("invalid opcode %q", s)
}

// StringToCode converts the text representation or "CODE"+value to an EDNS0 code
// Inverse of [CodeToString].
func StringToCode(s string) (uint16, error) {
	s2 := strings.ToUpper(s)
	if c1, ok := dns.StringToCode[s2]; ok {
		return c1, nil
	}
	c2, ok := strings.CutPrefix(s2, "CODE")
	if ok {
		c3, err := strconv.ParseUint(c2, 10, 16)
		if err == nil {
			return uint16(c3), nil
		}
	}
	return uint16(0), fmt.Errorf("invalid code %q", s)
}

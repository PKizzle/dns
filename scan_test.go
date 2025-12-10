package dns

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestZoneParser(t *testing.T) {
	testcases := []struct {
		name   string
		input  string
		output []RR
		err    error
	}{
		{
			"$generate",
			"$ORIGIN example.org.\n$GENERATE 10-12 foo${2,3,d} IN A 127.0.0.$",
			[]RR{
				&A{Hdr: Header{Name: "foo012.example.org.", Class: ClassINET}, A: netip.MustParseAddr("127.0.0.10")},
				&A{Hdr: Header{Name: "foo013.example.org.", Class: ClassINET}, A: netip.MustParseAddr("127.0.0.11")},
				&A{Hdr: Header{Name: "foo014.example.org.", Class: ClassINET}, A: netip.MustParseAddr("127.0.0.12")},
			},
			nil,
		},
		{
			"aaaa",
			"1.example.org. 600 IN AAAA ::1\n2.example.org. 600 IN AAAA ::FFFF:127.0.0.1",
			[]RR{
				&AAAA{Hdr: Header{Name: "1.example.org.", Class: ClassINET}, AAAA: netip.IPv6Loopback()},
				&AAAA{Hdr: Header{Name: "2.example.org.", Class: ClassINET}, AAAA: netip.MustParseAddr("::FFFF:127.0.0.1")},
			},
			nil,
		},
		{"badaddr1", "1.bad.example.org. 600 IN A ::1", nil, &Error{`bad A A: "::1"`}},
		{"baddaddr2", "2.bad.example.org. 600 IN A ::FFFF:127.0.0.1", nil, &Error{`bad A A:`}},
		{"badaddr3", "3.bad.example.org. 600 IN AAAA 127.0.0.1", nil, &Error{`bad AAAA AAAA:`}},
		{
			"unknown-rdata",
			"example. 3600 tYpe44 \\# 03 75  0100",
			[]RR{&SSHFP{Hdr: Header{Name: "example.", Class: ClassINET}, Algorithm: 117, Type: 1, FingerPrint: "00"}},
			nil,
		},
		{
			"unknown-without-rdata",
			"example. 3600 CLASS1 TYPE1 \\# 0",
			[]RR{&A{Hdr: Header{Name: "example.", Class: ClassINET}}},
			nil,
		},
		{
			"unknown-toolong",
			"example. 3600 CLASS1 TYPE1 \\# 65536 " + strings.Repeat("00 ", 65536),
			nil,
			&Error{err: "bad RFC3597 Rdata"},
		},
		{"openescape", "example.net IN CNAME example.net.", nil, nil},
		{"bad-openescape", "example.net IN CNAME example.org\\", nil, &Error{"bad owner name:"}},
		{"badtarget-cname", "bad.example.org. CNAME ; bad cname", nil, &Error{"missing TTL with no"}},
		{"badtarget-http", "bad.example.org. HTTPS 10 ; bad https", nil, &Error{"missing TTL with no"}},
		{"badtarget-mx", "bad.example.org. MX 10 ; bad mx", nil, &Error{"missing TTL with no"}},
		{"badtarget-srv", "bad.example.org. SRV 1 0 80 ; bad srv", nil, &Error{"missing TTL with no"}},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			z := NewZoneParser(strings.NewReader(tc.input), "", "")
			i := 0
			for rr, ok := z.Next(); ok; rr, ok = z.Next() {
				if !Equal(rr, tc.output[i]) {
					t.Errorf("expected %s to equal to %s", rr, tc.output[i])
				}
				i++
			}
			if tc.err != nil {
				if !strings.Contains(z.Err().Error(), tc.err.Error()) {
					t.Errorf("expected err to be %s, got %s", tc.err, z.Err())
				}
			}
		})
	}
}

func TestZoneParserInclude(t *testing.T) {
	tmpfile, _ := os.CreateTemp("", "dns")
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zone := "$ORIGIN example.org.\n$INCLUDE " + tmpfile.Name() + "\nbar\tIN\tA\t127.0.0.2"

	var got int
	z := NewZoneParser(strings.NewReader(zone), "", "")
	z.IncludeAllowFunc = func(string, string) bool { return true }
	for rr, ok := z.Next(); ok; _, ok = z.Next() {
		switch rr.Header().Name {
		case "foo.example.org.", "bar.example.org.":
		default:
			t.Fatalf("expected foo.example.org. or bar.example.org., but got %s", rr.Header().Name)
		}
		got++
	}
	if err := z.Err(); err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}

	if expected := 2; got != expected {
		t.Errorf("failed to parse zone after include, expected %d records, got %d", expected, got)
	}

	os.Remove(tmpfile.Name())

	z = NewZoneParser(strings.NewReader(zone), "", "")
	z.IncludeAllowFunc = func(string, string) bool { return true }
	z.Next()
	if err := z.Err(); err == nil ||
		!strings.Contains(err.Error(), "failed to open") ||
		!strings.Contains(err.Error(), tmpfile.Name()) ||
		!strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf(`expected error to contain: "failed to open", %q and "no such file or directory" but got: %s`,
			tmpfile.Name(), err)
	}
}

func TestZoneParserIncludeFS(t *testing.T) {
	fsys := fstest.MapFS{
		"db.foo": &fstest.MapFile{
			Data: []byte("foo\tIN\tA\t127.0.0.1"),
		},
	}
	zone := "$ORIGIN example.org.\n$INCLUDE db.foo\nbar\tIN\tA\t127.0.0.2"

	var got int
	z := NewZoneParser(strings.NewReader(zone), "", "")
	z.IncludeAllowFunc = func(string, string) bool { return true }
	z.SetIncludeFS(fsys)
	for rr, ok := z.Next(); ok; _, ok = z.Next() {
		switch rr.Header().Name {
		case "foo.example.org.", "bar.example.org.":
		default:
			t.Fatalf("expected foo.example.org. or bar.example.org., but got %s", rr.Header().Name)
		}
		got++
	}
	if err := z.Err(); err != nil {
		t.Fatalf("expected no error, but got %s", err)
	}

	if expected := 2; got != expected {
		t.Errorf("failed to parse zone after include, expected %d records, got %d", expected, got)
	}

	fsys = fstest.MapFS{}

	z = NewZoneParser(strings.NewReader(zone), "", "")
	z.IncludeAllowFunc = func(string, string) bool { return true }
	z.SetIncludeFS(fsys)
	z.Next()
	if err := z.Err(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf(`expected fs.ErrNotExist but got: %T %v`, err, err)
	}
}

func TestZoneParserIncludeFSPaths(t *testing.T) {
	fsys := fstest.MapFS{
		"baz/bat/db.foo": &fstest.MapFile{
			Data: []byte("foo\tIN\tA\t127.0.0.1"),
		},
	}

	for _, p := range []string{
		"../bat/db.foo",
		"/baz/bat/db.foo",
	} {
		zone := "$ORIGIN example.org.\n$INCLUDE " + p + "\nbar\tIN\tA\t127.0.0.2"
		var got int
		z := NewZoneParser(strings.NewReader(zone), "", "baz/quux/db.bar")
		z.IncludeAllowFunc = func(string, string) bool { return true }
		z.SetIncludeFS(fsys)
		for rr, ok := z.Next(); ok; _, ok = z.Next() {
			switch rr.Header().Name {
			case "foo.example.org.", "bar.example.org.":
			default:
				t.Fatalf("$INCLUDE %q: expected foo.example.org. or bar.example.org., but got %s", p, rr.Header().Name)
			}
			got++
		}
		if err := z.Err(); err != nil {
			t.Fatalf("$INCLUDE %q: expected no error, but got %s", p, err)
		}
		if expected := 2; got != expected {
			t.Errorf("$INCLUDE %q: failed to parse zone after include, expected %d records, got %d", p, expected, got)
		}
	}
}

func TestZoneParserIncludeDisallowed(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "dns")
	if err != nil {
		t.Fatalf("could not create tmpfile for test: %s", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString("foo\tIN\tA\t127.0.0.1"); err != nil {
		t.Fatalf("unable to write content to tmpfile %q: %s", tmpfile.Name(), err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("could not close tmpfile %q: %s", tmpfile.Name(), err)
	}

	zp := NewZoneParser(strings.NewReader("$INCLUDE "+tmpfile.Name()), "example.org.", "")

	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expect = "$INCLUDE directive not allowed"
	if err := zp.Err(); err == nil || !strings.Contains(err.Error(), expect) {
		t.Errorf("expected error to contain %q, got %v", expect, err)
	}
}

func TestZoneParserUnexpectedNewline(t *testing.T) {
	zone := `
example.com. 60 PX
1000 TXT 1K
`
	zp := NewZoneParser(strings.NewReader(zone), "example.com.", "")
	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
	}

	const expect = `dns: unexpected newline: "\n" at line: 2:18`
	if err := zp.Err(); err == nil || err.Error() != expect {
		t.Errorf("expected error to contain %q, got %v", expect, err)
	}

	// Test that newlines inside braces still work.
	zone = `
example.com. 60 PX (
1000 TXT 1K )
`
	zp = NewZoneParser(strings.NewReader(zone), "example.com.", "")

	var count int
	for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		count++
	}

	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}

	if err := zp.Err(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestZoneParserEscapedStringOffset(t *testing.T) {
	testcases := []struct {
		input          string
		inputOffset    int
		expectedOffset int
		expectedOK     bool
	}{
		{"simple string with no escape sequences", 20, 20, true},
		{"simple string with no escape sequences", 500, -1, true},
		{`\;\088\\\;\120\\`, 0, 0, true},
		{`\;\088\\\;\120\\`, 1, 2, true},
		{`\;\088\\\;\120\\`, 2, 6, true},
		{`\;\088\\\;\120\\`, 3, 8, true},
		{`\;\088\\\;\120\\`, 4, 10, true},
		{`\;\088\\\;\120\\`, 5, 14, true},
		{`\;\088\\\;\120\\`, 6, 16, true},
		{`\;\088\\\;\120\\`, 7, -1, true},
		{`\`, 3, 0, false},
		{`a\`, 3, 0, false},
		{`aa\`, 3, 0, false},
		{`aaa\`, 3, 3, true},
		{`aaaa\`, 3, 3, true},
	}
	for i, tc := range testcases {
		outputOffset, outputOK := escapedStringOffset(tc.input, tc.inputOffset)
		if outputOffset != tc.expectedOffset {
			t.Errorf("test %d (input %#q offset %d) returned offset %d but expected %d",
				i, tc.input, tc.inputOffset, outputOffset, tc.expectedOffset,
			)
		}
		if outputOK != tc.expectedOK {
			t.Errorf("test %d (input %#q offset %d) returned ok=%t but expected %t",
				i, tc.input, tc.inputOffset, outputOK, tc.expectedOK,
			)
		}
	}
}

func TestZoneParserEDNS0(t *testing.T) {
	testcases := []struct {
		name string
		in   EDNS0
		exp  string
	}{
		{
			"zoneversion", &ZONEVERSION{Labels: 4, Type: 0, Version: []byte{1, 2, 3, 4}},
			".  CLASS0 ZONEVERSION 4 SOA-SERIAL 16909060",
		},
		{
			"ede-extratext", &EDE{InfoCode: 15, ExtraText: "bla"},
			`.  CLASS0 EDE 15 "Blocked": "bla"`,
		},
		{
			"ede", &EDE{InfoCode: 15},
			`.  CLASS0 EDE 15 "Blocked": ""`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ednsrr := tc.in.String()
			parsed := dnstestNew(ednsrr)
			s := strings.Replace(parsed.String(), "\t", " ", -1)
			if s != tc.exp {
				t.Errorf("expected %s, got %s", tc.exp, s)
			}
		})
	}
}

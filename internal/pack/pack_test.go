package pack

import (
	"testing"
)

func TestName(t *testing.T) {
	testcases := []struct {
		in string
		ok bool
	}{
		{`www\.this.is.\131an.example.org.`, true},
		{`www.example.org.`, true},
		{`www.example.org`, true},
		{`org.`, true},
		{`.`, true},
		{`..`, false},
		{`.org`, false},
		{`www..example.org.`, false},
		{`www.example.org..`, false},
	}
	buf := make([]byte, 256)
	for _, tc := range testcases {
		_, got := Name(tc.in, buf, 0, nil, false)
		if (got == nil) != tc.ok {
			t.Errorf("expected %t for name %q: %v", tc.ok, tc.in, got)
		}
	}
}

func BenchmarkName(b *testing.B) {
	buf := make([]byte, 256)
	s := "wwww.example.org."
	for i := 0; i < b.N; i++ {
		Name(s, buf, 0, nil, false)
	}
}

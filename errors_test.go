package dns

import (
	"errors"
	"testing"
)

func TestErrorFmtUnwrap(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel *Error
		wantIs   bool
	}{
		{"ErrKey wrapped", ErrKey.Fmt(": HMAC sign"), ErrKey, true},
		{"ErrKeyAlg wrapped", ErrKeyAlg.Fmt(": HMAC sign"), ErrKeyAlg, true},
		{"ErrSig wrapped", ErrSig.Fmt(": HMAC verify"), ErrSig, true},
		{"ErrTime wrapped", ErrTime.Fmt(": check"), ErrTime, true},
		{"ErrKey vs ErrKeyAlg", ErrKeyAlg.Fmt(": HMAC sign"), ErrKey, false},
		{"ErrSig vs ErrKey", ErrSig.Fmt(": HMAC verify"), ErrKey, false},
		{"bare sentinel", ErrKey, ErrKey, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.sentinel); got != tt.wantIs {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.err, tt.sentinel, got, tt.wantIs)
			}
		})
	}
}

func TestErrorFmtDoubleFmt(t *testing.T) {
	// Fmt of a Fmt should still unwrap to the original sentinel.
	wrapped := ErrKey.Fmt(": first")
	double := wrapped.(*Error).Fmt(": second")

	if !errors.Is(double, ErrKey) {
		t.Errorf("errors.Is(double-wrapped, ErrKey) = false, want true")
	}
	if double.Error() != "dns: bad key: first: second" {
		t.Errorf("double.Error() = %q, want %q", double.Error(), "dns: bad key: first: second")
	}
}

func TestErrorFmtPreservesMessage(t *testing.T) {
	err := ErrKey.Fmt(": HMAC sign")
	if err.Error() != "dns: bad key: HMAC sign" {
		t.Errorf("err.Error() = %q, want %q", err.Error(), "dns: bad key: HMAC sign")
	}
}

func TestErrorUnwrapNilForSentinel(t *testing.T) {
	// Sentinel errors themselves have no parent.
	if ErrKey.Unwrap() != nil {
		t.Errorf("ErrKey.Unwrap() = %v, want nil", ErrKey.Unwrap())
	}
}

package dnsutil

import (
	"testing"
)

func TestStringToMsg(t *testing.T) {
	testcases := []struct {
		in  string
		out string
	}{
		{
			in: `
;; QUESTION: 1, PSEUDO: 0, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 0

;; QUESTION SECTION:
miek.nl.                IN      MX

;; ANSWER SECTION:
miek.nl.        11381   IN      MX      10 aspmx2.googlemail.com.
miek.nl.        11381   IN      MX      10 aspmx3.googlemail.com.
miek.nl.        11381   IN      MX      5 alt1.aspmx.l.google.com.
miek.nl.        11381   IN      MX      5 alt2.aspmx.l.google.com.
miek.nl.        11381   IN      MX      1 aspmx.l.google.com.`,
			out: "",
		},
	}
	for _, tc := range testcases {
		m, err := StringToMsg(tc.in)
		if err != nil {
			t.Error(err)
		}
		println(m.String())
	}
}

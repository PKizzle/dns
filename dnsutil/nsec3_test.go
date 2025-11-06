package dnsutil

import (
	"testing"
)

func TestNSEC3Name(t *testing.T) {
	testcases := []struct {
		in, exp string
	}{
		{"example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"},
		{"c.", "0va5bpr2ou0vk0lbqeeljri88laipsfh"},
	}

	for _, tc := range testcases {
		got := NSEC3Name(tc.in, "aabbccdd", 12)
		if got != tc.exp {
			t.Errorf("test %d, expected %s, got %s", i, tc.exp, got)
		}
	}
	/*
				// positive tests
				{ // name hash between owner hash and next hash
					rr: &NSEC3{
						Hdr:  Header{Name: "2N1TB3VAIRUOBL6RKDVII42N9TFMIALP.com."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "PT3RON8N7PM3A0OE989IB84OOSADP7O8",
					},
					name:   "bsd.com.",
					covers: true,
				},
				{ // end of zone, name hash is after owner hash
					rr: &NSEC3{
						Hdr:  Header{Name: "3v62ulr0nre83v0rja2vjgtlif9v6rab.com."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "2N1TB3VAIRUOBL6RKDVII42N9TFMIALP",
					},
					name:   "csd.com.",
					covers: true,
				},
				{ // end of zone, name hash is before beginning of zone
					rr: &NSEC3{
						Hdr:  Header{Name: "PT3RON8N7PM3A0OE989IB84OOSADP7O8.com."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "3V62ULR0NRE83V0RJA2VJGTLIF9V6RAB",
					},
					name:   "asd.com.",
					covers: true,
				},
				// negative tests
				{ // too short owner name
					rr: &NSEC3{
						Hdr:  Header{Name: "nl."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "39P99DCGG0MDLARTCRMCF6OFLLUL7PR6",
					},
					name:   "asd.com.",
					covers: false,
				},
				{ // outside of zone
					rr: &NSEC3{
						Hdr:  Header{Name: "39p91242oslggest5e6a7cci4iaeqvnk.nl."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "39P99DCGG0MDLARTCRMCF6OFLLUL7PR6",
					},
					name:   "asd.com.",
					covers: false,
				},
				{ // empty interval
					rr: &NSEC3{
						Hdr:  Header{Name: "2n1tb3vairuobl6rkdvii42n9tfmialp.com."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "2N1TB3VAIRUOBL6RKDVII42N9TFMIALP",
					},
					name:   "asd.com.",
					covers: false,
				},
				{ // empty interval wildcard
					rr: &NSEC3{
						Hdr:  Header{Name: "2n1tb3vairuobl6rkdvii42n9tfmialp.com."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "2N1TB3VAIRUOBL6RKDVII42N9TFMIALP",
					},
					name:   "*.asd.com.",
					covers: true,
				},
				{ // name hash is before owner hash, not covered
					rr: &NSEC3{
						Hdr:  Header{Name: "3V62ULR0NRE83V0RJA2VJGTLIF9V6RAB.com."},
						Hash: 1, Flags: 1, Iterations: 5, Salt: "F10E9F7EA83FC8F3",
						NextDomain: "PT3RON8N7PM3A0OE989IB84OOSADP7O8",
					},
					name:   "asd.com.",
					covers: false,
				},
			} {
				covers := tc.rr.Cover(tc.name)
				if tc.covers != covers {
					t.Fatalf("cover failed for %s: expected %t, got %t [record: %s]", tc.name, tc.covers, covers, tc.rr)
				}
			}
		}
	*/
}

package dbfile_test

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atom"
)

func TestDbfileTransfer(t *testing.T) {
	testcases := []struct {
		name    string
		input   string
		success bool
	}{
		{
			"axfr",
			`example.org {
				dbfile zone/testdata/db.example.org {
					transfer
			    }
			}`, true,
		},
		{
			"no-axfr",
			`example.org {
				dbfile zone/testdata/db.example.org
			}`, false,
		},
		{
			"axfr",
			`example.org {
				dbfile zone/testdata/db.example.org {
				 	transfer {
						to {
							notify 127.0.0.1
						}
					}
				}
			}`, false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			server, cancel, err := atom.NewTest(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()

			c := new(dns.Client)
			addrs := server.Addr()
			m := dns.NewMsg("example.org.", dns.TypeAXFR)
			env, err := c.TransferIn(context.TODO(), m, "tcp", addrs[1])
			if err != nil {
				if !tc.success {
					return
				}
				t.Fatalf("failed to setup zone transfer in: %s", err)
			}

			i := 0 // expect at least more then 1 record, last one should be SOA.
			var last dns.RR
			for e := range env {
				if e.Error != nil {
					if tc.success {
						t.Fatalf("got unexpected error: %s", e.Error)
					}
					return
				}
				last = e.Answer[len(e.Answer)-1]
				i++
			}
			if i == 0 {
				t.Fatal("expected more than 0 records")
			}
			if _, ok := last.(*dns.SOA); !ok {
				t.Fatal("last record should be SOA")
			}
		})
	}
}

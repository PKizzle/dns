package dbfile

import "codeberg.org/miekg/dns"

// Transfer implements the transfer.Transfer interface.
func (d *Dbfile) TransferOut() error {
	// get soa and apex
	apex, err := z.ApexIfDefined()
	if err != nil {
		return nil, err
	}

	ch := make(chan []dns.RR)
	go func() {
		if serial != 0 && apex[0].(*dns.SOA).Serial == serial { // ixfr fallback, only send SOA
			ch <- []dns.RR{apex[0]}

			close(ch)
			return
		}

		ch <- apex
		z.Walk(func(e *tree.Elem, _ map[uint16][]dns.RR) error { ch <- e.All(); return nil })
		ch <- []dns.RR{apex[0]}

		close(ch)
	}()

	return ch, nil
}

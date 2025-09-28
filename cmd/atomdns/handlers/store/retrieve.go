package store

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func (s *Store) Retrieve(m *dns.Msg) *dns.Msg {
	qname := m.Question[0].Header().Name
	qlabels := dnsutil.Labels(qname)
	labels := 0

	for i, start := dnsutil.Prev(qname, labels); !start; i, start = dnsutil.Prev(qname, labels) {
		node, ok := s.Get(qname[i:])
		if ok {
			if node.Rcode == dns.RcodeNameError {
				return s.NodeFound(m, node)
			}
			// TODO(miek): remove
			println(labels, qlabels)
			if labels == qlabels { // -1???
				// matched entire name, then also return, otherwise continue
				return s.NodeFound(m, node)
			}
		}
		labels++
	}
	return nil
}

func (s *Store) NodeFound(m *dns.Msg, node Node) *dns.Msg {
	r := new(dns.Msg)
	r.ID = m.ID
	r.Response = true
	r.Opcode = m.Opcode
	if r.Opcode == dns.OpcodeQuery {
		r.RecursionDesired = m.RecursionDesired
		r.CheckingDisabled = m.CheckingDisabled
		r.Security = m.Security
	}
	r.Rcode = node.Rcode
	r.Question = []dns.RR{m.Question[0]}
	r.Answer = node.Answer
	r.Ns = node.Ns
	r.Extra = node.Extra
	return r
}

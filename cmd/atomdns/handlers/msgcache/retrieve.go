package msgcache

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func (m *Msgcache) Retrieve(x *dns.Msg) *dns.Msg {
	qname := x.Question[0].Header().Name
	qtype := dns.RRToType(x.Question[0])
	qlabels := dnsutil.Labels(qname)
	labels := 0

	for i, start := dnsutil.Prev(qname, labels); !start; i, start = dnsutil.Prev(qname, labels) {
		node, ok := m.Get(qname[i:])
		if ok {
			if node.Rcode == dns.RcodeNameError {
				return m.NodeFound(x, node)
			}
			if labels == qlabels && qtype == node.Type {
				return m.NodeFound(x, node)
			}
		}
		labels++
	}
	return nil
}

func (m *Msgcache) NodeFound(x *dns.Msg, node Node) *dns.Msg {
	r := new(dns.Msg)
	r.ID = x.ID
	r.Response = true
	r.Opcode = x.Opcode
	if r.Opcode == dns.OpcodeQuery {
		r.RecursionDesired = x.RecursionDesired
		r.CheckingDisabled = x.CheckingDisabled
		r.Security = x.Security
	}
	r.Rcode = node.Rcode
	r.Question = []dns.RR{x.Question[0]}
	r.Answer = node.Answer
	r.Ns = node.Ns
	r.Extra = node.Extra
	return r
}

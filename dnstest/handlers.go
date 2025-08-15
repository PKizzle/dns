package dnstest

// do not define handler here. Also like the coredns's server.go a lot better.

/*
func HelloHandlerBadID(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.ID++

	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{"Hello world"}}
	m.Pack()

	io.Copy(w, m)
}

func HelloHandlerBadThenGoodID(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.ID++

	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{"Hello world"}}

	m.Pack()
	io.Copy(w, m)

	m.ID--

	m.Pack()
	io.Copy(w, m)
}

func HelloHandlerEchoAddrPort(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)

	remoteAddr := w.RemoteAddr().String()
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, Txt: []string{remoteAddr}}

	m.Pack()

	io.Copy(w, m)
}
*/

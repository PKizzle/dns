/*
Package dns implements a full featured interface to the Domain Name System. Both server- and client-side programming is supported.

The package allows complete control over what is sent out to the DNS. The API follows the less-is-more principle, by presenting a small, clean interface.

It supports (asynchronous) querying/replying, incoming/outgoing zone transfers,
TSIG, EDNS0, dynamic updates, notifies and DNSSEC validation/signing.

Resource records (RRs) are native types. They are not stored in wire format. Everything is modelled or made to look like a RR.
The question section holds an RR and the EDNS0 option codes are also RRs.

Basic usage pattern for creating a new resource record:

	r ;= &MX{Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600}, Preference: 10, Mx: "mx.miek.nl."}

Or directly from a string (which is slower):

	mx, err := dns.New("miek.nl. 3600 IN MX 10 mx.miek.nl.")

Or when the default origin (.) and TTL (3600) and class (IN) suit you:

	mx, err := dns.New("miek.nl MX 10 mx.miek.nl")

Or even:

	mx, err := dns.New("$ORIGIN nl.\nmiek 1H IN MX 10 mx.miek")

In the DNS messages are exchanged, these messages contain resource records (sets). Use pattern for creating a message:

	m := new(dns.Msg)
	m.Question = []dns.RR{mx}

The message m is now a message with the question section set to ask the MX records for the miek.nl. zone. Or when making an actual request.

	m.ID = dns.ID()
	m.RecursionDesired = true

After creating a message it can be sent. Basic use pattern for synchronous querying the DNS at a server configured on 127.0.0.1 and port 53 using UDP:

	c := new(dns.Client)
	in, rtt, err := c.Exchange(m1, "udp", "127.0.0.1:53")

When this functions returns you will get DNS message. A DNS message consists out of four (five in this package) sections.
The question section: in.Question, the answer section: in.Answer,
the authority section: in.Ns and the additional section: in.Extra. And the extra and new fifth the pseudo section: in.Pseudo, see [Msg].

Each of these sections contain a []RR. Basic use pattern for accessing the rdata of a TXT RR as the first RR in
the Answer section:

	if t, ok := in.Answer[0].(*dns.TXT); ok {
		// do something with t.Txt
	}

# Domain Name and TXT Character String Representations

Both domain names and TXT character strings are converted to presentation form
both when unpacked and when converted to strings.

For TXT character strings, tabs, carriage returns and line feeds will be
converted to \t, \r and \n respectively. Back slashes and quotations marks will
be escaped. Bytes below 32 and above 127 will be converted to \DDD form.

For domain names, in addition to the above rules brackets, periods, spaces,
semicolons and the at symbol are escaped.

# DNSSEC

DNSSEC (DNS Security Extension) adds a layer of security to the DNS. It uses
public key cryptography to sign resource records. The public keys are stored in
DNSKEY records and the signatures in RRSIG records.

Requesting DNSSEC information for a zone is done by adding the DO (DNSSEC OK)
bit to a request.

	m := new(dns.Msg)
	m.Security = true
	m.UDPSize = 4096

Signature generation, signature verification and key generation are all supported. See [RRSIG].

# EDNS0

EDNS0 is an extension mechanism for the DNS defined in RFC 2671 and updated by
RFC 6891. It defines a new RR type, the OPT RR, which is then completely abused.

In this package all EDNS0 options are implemented as RR, doing basic "EDNS0" things, like
setting the DNSSEC OK bit (DO) or the UDP buffer size is handled for you. See [Msg].

The data of an OPT RR sits in the [Msg.Pseudo[ section consists out of a slice of EDNS0 (RFC 6891) interfaces.
These are just RRs with an extra Pseudo() method.

Basic use pattern for a server to check if (and which) options are set:

	for _, o := range msg.Pseudo {
		switch x := o.(type) {
		case *dns.NSID:
			// do stuff with x.Nsid
		case *dns.SUBNET:
			// access x.Family, x.Address, etc.
		}
	}

SIG(0)

From RFC 2931:

	SIG(0) provides protection for DNS transactions and requests ....
	... protection for glue records, DNS requests, protection for message headers
	on requests and responses, and protection of the overall integrity of a response.

It works like TSIG, except that SIG(0) uses public key cryptography, instead of
the shared secret approach in TSIG. Supported algorithms: ECDSAP256SHA256,
ECDSAP384SHA384, RSASHA1, RSASHA256 and RSASHA512.

Signing subsequent messages in multi-message sessions is not implemented.
*/
package dns

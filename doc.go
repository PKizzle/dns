/*
Package dns implements a full featured interface to the Domain Name System.
Both server- and client-side programming is supported. The package allows
complete control over what is sent out to the DNS. The API follows the
less-is-more principle, by presenting a small, clean interface.

It supports (asynchronous) querying/replying, incoming/outgoing zone transfers,
TSIG, EDNS0, dynamic updates, notifies and DNSSEC validation/signing.

Resource records are native types. They are not stored in wire format. Basic
usage pattern for creating a new resource record:

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

More advanced options are available using a net.Dialer and the corresponding API.
For example it is possible to set a timeout, or to specify a source IP address
and port to use for the connection:
TODO - different

	c := new(dns.Client)
	laddr := net.UDPAddr{
		IP: net.ParseIP("[::1]"),
		Port: 12345,
		Zone: "",
	}
	c.Dialer = &net.Dialer{
		Timeout: 200 * time.Millisecond,
		LocalAddr: &laddr,
	}
	in, rtt, err := c.Exchange(m1, "udp", "8.8.8.8:53")

If these "advanced" features are not needed, a simple UDP query can be sent with:

	in, err := dns.Exchange(m, "udp", "127.0.0.1:53")

When this functions returns you will get DNS message. A DNS message consists out of four (five in this package) sections.
The question section: in.Question, the answer section: in.Answer,
the authority section: in.Ns and the additional section: in.Extra. And the fifth the pseud section: in.Pseudo, see [Msg].

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

# Transaction signature

An TSIG or transaction signature adds a HMAC TSIG record to each message sent.
The supported algorithms include: HmacSHA1, HmacSHA256 and HmacSHA512.

Basic use pattern when querying with a TSIG name "axfr." (note that these key names
must be fully qualified - as they are domain names) and the base64 secret
"so6ZGir4GPAqINNh9U5c3A==":

If an incoming message contains a TSIG record it MUST be the last record in
the additional section (RFC2845 3.2).  This means that you should make the
call to SetTsig last, right before executing the query.  If you make any
changes to the RRset after calling SetTsig() the signature will be incorrect.

	c := new(dns.Client)
	c.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeMX)
	m.SetTsig("axfr.", dns.HmacSHA256, 300, time.Now().Unix())
	...
	// When sending the TSIG RR is calculated and filled in before sending

When requesting an zone transfer (almost all TSIG usage is when requesting zone
transfers), with TSIG, this is the basic use pattern. In this example we
request an AXFR for miek.nl. with TSIG key named "axfr." and secret
"so6ZGir4GPAqINNh9U5c3A==" and using the server 176.58.119.54:

	t := new(dns.Transfer)
	m := new(dns.Msg)
	t.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	m.SetAxfr("miek.nl.")
	m.SetTsig("axfr.", dns.HmacSHA256, 300, time.Now().Unix())
	c, err := t.In(m, "176.58.119.54:53")
	for r := range c { ... }

You can now read the records from the transfer as they come in. Each envelope
is checked with TSIG. If something is not correct an error is returned.

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

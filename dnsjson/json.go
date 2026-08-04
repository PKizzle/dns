package dnsjson

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/pkg/pool"
	"golang.org/x/crypto/cryptobyte"
)

// Marshal returns the JSON (RFC 8427) representation of [dns.RR] as defined in [RR]. If more than one
// [dns.RR] is given it is assumed this represents a [RRset].
func Marshal(rrs ...dns.RR) ([]byte, error) {
	if len(rrs) == 0 {
		return nil, nil
	}
	buf := jsonPool.Get()
	defer jsonPool.Put(buf)

	jrr := &RR{
		Name:      rrs[0].Header().Name,
		TTL:       rrs[0].Header().TTL,
		TypeName:  dnsutil.TypeToString(dns.RRToType(rrs[0])),
		ClassName: dnsutil.ClassToString(rrs[0].Header().Class),
	}

	switch len(rrs) {
	case 1:
		if l := rrs[0].Len(); cap(buf) < l {
			buf = make([]byte, l)
		}

		off, _ := dns.Zpack(rrs[0], buf, 0, nil)
		jrr.RdataHex = hex.EncodeToString(buf[:off])
	default:
		jrr.RRset = make([]RRset, len(rrs))
		for i, rr := range rrs {
			if l := rr.Len(); cap(buf) < l {
				buf = make([]byte, l)
			}

			off, _ := dns.Zpack(rr, buf, 0, nil)
			jrr.RRset[i].RdataHex = hex.EncodeToString(buf[:off])
		}
	}

	return json.Marshal(jrr)
}

// Unmarshal returns the [dns.RR] from the JSON (RFC 8427) object.
func Unmarshal(data []byte) ([]dns.RR, error) {
	jrr := &RR{}
	err := json.Unmarshal(data, jrr)
	if err != nil {
		return nil, err
	}
	rrs := []dns.RR{}
	if len(jrr.RRset) > 0 {
		rrs = make([]dns.RR, len(jrr.RRset))
	}

	newfn := func() dns.RR { return nil }
	switch {
	case jrr.Type > 0:
		newfn = dns.TypeToRR[jrr.Type]
	case jrr.TypeName != "":
		newfn = dns.TypeToRR[dns.StringToType[jrr.TypeName]]
	default:
		return nil, fmt.Errorf("bad RR type")
	}

	class := uint16(0)
	switch {
	case jrr.Class > 0:
		class = jrr.Class
	case jrr.ClassName != "":
		class, _ = dns.StringToClass[jrr.ClassName]
	default:
		return nil, fmt.Errorf("bad RR class")
	}

	switch len(rrs) {
	case 1:
		rrs[0] = newfn()

		rrs[0].Header().Name = jrr.Name
		rrs[0].Header().TTL = jrr.TTL
		rrs[0].Header().Class = class

		data, err := hex.DecodeString(jrr.RdataHex)
		if err != nil {
			return nil, err
		}
		if err := dns.Zunpack(rrs[0], cryptobyte.String(data), nil); err != nil {
			return nil, err
		}
	default:
		for i := range rrs {
			rrs[i] = newfn()

			rrs[i].Header().Name = jrr.Name
			rrs[i].Header().TTL = jrr.TTL
			rrs[i].Header().Class = class

			data, err := hex.DecodeString(jrr.RRset[i].RdataHex)
			if err != nil {
				return nil, err
			}
			if err := dns.Zunpack(rrs[i], cryptobyte.String(data), nil); err != nil {
				return nil, err
			}
		}
	}

	return rrs, nil
}

// jsonPool pools allocations to encode/decode to wire format.
var jsonPool = pool.New(dns.DefaultMsgSize)

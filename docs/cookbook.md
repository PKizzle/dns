# DNS Cookbook

The file documents how to do common tasks.

In general, the code is well-documented. This document is meant to point you in
the right direction. It's usually best to read the comments in the code for more details.

## Terminology

* `RR`: A resource-record. It is made up of a header and the rdata.  Example: `foo.example.com. IN MX 0 mx.example.com.`
* `RDATA`: resource-data. The a header and the rdata.  Example: `0 mx.example.com.`

## Convert between text and enums

rtypes:

```
num := dns.StringToType["MX"]
typeStr := dnsutil.TypeToString(t uint16) string {
```

## Create an empty RR

Basic usage pattern for creating a new resource record:

```
rr := dns.TypeToRR[rdtype]()
```

## Create an RR and populate it

```
rr := &dns.MX{Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
```

Or directly from a string (which is much slower):

```
mx, err := dns.New("miek.nl. 3600 IN MX 10 mx.miek.nl.")
```

Or when the default origin (.) and TTL (3600) and class (IN) suit you:

```
mx, err := dns.New("miek.nl MX 10 mx.miek.nl")
```

Or even:

```
mx, err := dns.New("$ORIGIN nl.\nmiek 1H IN MX 10 mx.miek")
```

Or with dnstest.New, if you are sure no error will occur:

```
mx := dnstest.New("miek.nl.  IN MX 10 mx.miek.nl.")
```

## Replace the header of an RR

```
*(rr.Header()) = dns.Header{Name: rc.NameFQDN + ".", Class: dns.ClassINET}
    or
hdr := rr.Header()
*hdr = dns.Header{Name: rc.NameFQDN + ".", Class: dns.ClassINET}
    or
rr.Header().Name = "example.com."
rr.Header().Class = dns.ClassINET
```

## Access the RDATA of an RR

```
rr := &dns.MX{Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
rd := rr.DATA()
```

rr.DATA() is a copy. Here's proof:

```
rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
rh := rr.Header()
rd := rr.Data()
fmt.Println("An RR split out into header and data:")
fmt.Printf("rr = %v\n", rr)
fmt.Printf("rh = %v\n", rh)
fmt.Printf("rd = %v\n", rd)
fmt.Println()

// Update RDATA
fmt.Println("Updating rr.Preference does not affect rd.  rd is a copy.")
rr.Preference = 20          //
fmt.Printf("rr = %v\n", rr) // Changed
fmt.Printf("rd = %v\n", rd) // Not changed.  rd is a copy.
fmt.Println()

// rd.(rdata.MX).Preference = 30
// cannot assign to rd.(rdata.MX).Preference (neither addressable nor a map index expression)

fmt.Println("Updating rdmx.Preference does not affect rr or rd.  rdmx is a copy.")
rdmx := rd.(rdata.MX)
rdmx.Preference = 40
fmt.Printf("rr = %v\n", rr)     // Unchanged
fmt.Printf("rd = %v\n", rd)     // Unchanged
fmt.Printf("rdmx = %v\n", rdmx) // Changed
fmt.Println()
}

/* Output:
An RR split out into header and data:
rr = miek.nl.	3600	IN	MX	10 mx.miek.nl.
rh = miek.nl.	3600	IN
rd = 10 mx.miek.nl.

Updating rr.Preference does not affect rd.  rd is a copy.
rr = miek.nl.	3600	IN	MX	20 mx.miek.nl.
rd = 10 mx.miek.nl.

Updating rdmx.Preference does not affect rr or rd.  rdmx is a copy.
rr = miek.nl.	3600	IN	MX	20 mx.miek.nl.
rd = 10 mx.miek.nl.
rdmx = 40 mx.miek.nl.
*/
```

## Register a non-standard rtype

Sure, you love A, CNAME, MX and other rtypes. What if your code needs a custom type?

Read about the `Typer` interface in `dns.go` for instructions how.


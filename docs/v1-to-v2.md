# Converting from v1 to v2

## What changed?

A lot. Here's a list.


## General tips:

None of these are required but experience has proven them to be good ideas.

1. Convert to netip.Addr first.

Before you convert to dns v2, convert from `net.IP` to `netip.Addr`. DNS v2
uses `netip.Addr` to represent IP addresses. Converting two modules at the same
time is much more difficult than converting them in sequence.

2. Make v1 and v2 coexist, then work to eliminate v1

If you make v1 and v2 coexist your conversion will be easier. You can work incrementally
instead of one big "big bang" change.  You can identify code that needs to be upgraded
by searching for `dnsv1.`

Code that uses both will have imports that look like:

```
    import (
        dnsv1 "github.com/miekg/dns"
        "codeberg.org/miekg/dns"
    )
```

Here's how to do it:

Step 1: Rename v1 to dnsv1

Change all imports from

    "github.com/miekg/dns"

to

    dnsv1 "github.com/miekg/dns"

Now v1 and v2 can co-exist.  `dnsv1.RR` is the old code and `dns.RR` is the new code.

You might consider shipping a release that has this one change. This should be a "no op" change
and therefore no tests should fail, no features should break.  Now you have a baseline
before other changes are made. 

ProTip: VSCode makes this easy.  Find code that mentions `dns.` and use "Rename Symbol"
(F2) to change it to `dnsv1.`.  VSCode does all the work of finding all instances. It even
updates the imports line.

For example, I found `dns.IP`, moved the cursor to the "d" in `dns`,
and pressed F2. Renamed `dns` to `dnsv1`.

You'll need to do this once for each file. VSCode is smart enough to know that imports are per-file, even though Rename Symbol can work across multiple files.

Find the files that need this change:

    grep -l -R -r --include='*.go' github.com/miekg/dns/dns

3. Do this for dnsutils and other packages

Do something similar for `dnsutil` (`dnsutilv1`) also.

Again, this isn't required, just useful.

3. Work incrementally

It's best to convert a little, test, convert a little more, test, etc.  Trying to convert
everything makes testing difficult.

Doing this requires you to be able to convert between v1's `RR` and v2's `RR`.

Here are some conversion functions.  The functions are slow and ugly, but accuracy is more important. (The functions being slow is ok because they are temporary.  The slowness should give you incentive to finish porting to v2!

```
package dnsrr

import (
        dnsv2 "codeberg.org/miekg/dns"
        dnsv1 "github.com/miekg/dns"
)

// RRv1tov2 converts github.com/miekg/dns (v1) RR to codeberg.org/miekg/dns (v2) RR.
// Typically used in providers that still use v1.
// Note: this function is not efficient. It converts via string representation.
// Use it until you are able to convert to v2 fully.
// Note: Panics on error.
func RRv1tov2(rrv1 dnsv1.RR) dnsv2.RR {
        rrv2, err := dnsv2.New(rrv1.String())
        if err != nil {
                panic("Failed to convert RR to v2: " + err.Error())
        }
        return rrv2
}

// RRv2tov1 converts codeberg.org/miekg/dns (v2) RR to github.com/miekg/dns (v1) RR.
// Typically used in providers that still use v1.
// Note: this function is not efficient. It converts via string representation.
// Use it until you are able to convert to v1 fully.
// Note: Panics on error.
func RRv2tov1(rrv2 dnsv2.RR) dnsv1.RR {
        rrv1, err := dnsv1.NewRR(rrv2.String())
        if err != nil {
                panic("Failed to convert RR to v1: " + err.Error())
        }
        return rrv1
}
```

## Converting idioms

Here are some v1 vs v2 changes:

### What type is this RR?  (and convert to a string)

OLD:

    header := rr.Header()
    rrtype := header.Rrtype
    typeStr := dns.TypeToString[header.Rrtype]

NEW:

    rrtype := dns.RRToType(rr)
    rrtypeStr := dns.TypeToString[rrtype]

### Canonicalize a DNS name:

OLD:

    id := dns.CanonicalName(foo)

NEW:

    id := dnsutil.Canonical(foo)

### Find the TTL

OLD:

    rr.Header().Ttl

NEW:

    rr.Header().TTL

### Permit $INCLUDE in zonefiles

OLD:

    zp := dns.NewZoneParser(...)
    zp.SetIncludeAllowed(true)

NEW:

    zp := dns.NewZoneParser(...)
    (nothing. that's the default)

### Reject $INCLUDE in zonefiles

OLD:

    zp := dns.NewZoneParser(...)
    zp.SetIncludeAllowed(false)

NEW:

    zp := dns.NewZoneParser(...)
    zp.IncludeAllowFunc = func() bool { return false }

## Useful idioms

See [cookbook.md] for useful idioms.

## Send us your suggestions!

Please add to this list!  The conversions you find will be useful to others.
Please submit a PR to this file!

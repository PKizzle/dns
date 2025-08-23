# Even more alternative approach to a DNS library (version 2)

Version 1 of miekg/dns didn't have any development guidelines, and although this went remarkably well for
years it is nice to give some guidance to new contributors and to lay out some of the design decisions.

## "Big" RRs

RR that have a lot of different rdata "types", like the SVCB record a sub-package should be created where
most of the types and methods should be located. For SVCB, the `svcb` package exist. Each sub-type should
be capitalized, as-if it is an RR. The public API for these sub-types should match the `RR` interface:

- String() string
- Len() int

Due to cyclic dependencies this creates some friction, but in the end it will be easier for end-users.

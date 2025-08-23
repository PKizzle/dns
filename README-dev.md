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

## Custom Types for uint8/16, etc

The `type Key uint16` looks nice and _is_ more type-safe, but then you need to convert to and from uint16 all
over the place - negating the type safety entirely. It might be helpful for documenting a type, the that
uint16 is probably not the most important details of your new resource record.

## Values like Rcode, Class etc.

If you have a bunch of values that certain types can take the are named: `ValueThing` and will need a
`ValueToString`/`StringToValue` map or function. `Thing` may or may not be capitalized. E.g. we have
`RcodeScucces` and `ClassINET`.

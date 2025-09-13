# sign

## Name

_sign_ - add DNSSEC records to zone files

## Description

The _sign_ handler is used to (DNSSEC) sign zones. In this process DNSSEC resource records are
added. The signatures that sign the resource records sets have an expiration date, this means the
signing process must be repeated before this expiration data is reached. Otherwise the zone's data
will go BAD (RFC 4035, Section 5.5). The _sign_ handler takes care of this.

_sign_ can work in conjunction with the _dbfile_ handler; this handelr **signs** the zone's files, and
_dbfile_ **serves** the zone's _data_.

For this handler to work at least one key is needed. This "Common Signing Key" will be used to sign the entire
zone, _sign_ does _not_ support the ZSK/KSK split, nor will it do key or algorithm rollovers - it just signs.

_sign_ will:

- (Re)-sign the zone with the CSK(s) when:

  - The last time the SOA record was signed is more than a 6 days ago. Each zone will have some jitter
    applied to the inception date.
  - The signature on the SOA only has 9 days left before expiring.

When signing it will:

- Create RRSIGs that have an inception of -3 hours (minus a jitter between 0 and 18 hours)
  and a expiration of +32 (plus a jitter between 0 and 5 days) days for every given DNSKEY.

- Add NSEC records for all names in the zone. The TTL for these is the negative cache TTL from the
  SOA record.

- Add or replace _all_ apex CDS/CDNSKEY records with the ones derived from the given keys. For
  each key two CDS are created one with SHA1 and another with SHA256.

- Update the SOA's serial number to the _Unix epoch_ of when the signing happens. This will
  overwrite _any_ previous serial number.

- Adjust TTLs to make RRSets expire before the signature expires. TTLs longer or within 20% of the
  expiration date are cut in half.

- If the source (unsigned) zone file changes, these are picked up immediately.

The state of each zone will be checked at 5 hour intervals. The modification time is checked every 5
minutes.

Keys are named (following BIND9): `K<name>+<alg>+<id>.key` and `K<name>+<alg>+<id>.private`.
The keys **must not** be included in your zone; they will be added by _sign_. These keys can be
generated with `ldns-keygen` or BIND9's `dnssec-keygen`. You don't have to adhere to this naming
scheme, but then you need to name your keys explicitly, see the `keys` directive.

A generated zone is written out in a file named `db.<name>.signed` in the directory named by the
`directory` directive.

## Syntax

```
sign FILE {
    key KEYFILE [KEYFILE]...
    directory DIRECTORY
}
```

- **FILE** is the input zone file to sign. If the path is relative, the path from the _root_ global handler will be prepended to it.
- `key` specifies the key(s) (there can be multiple) to sign the zone. Any metadata in these files (Activate, Publish, etc.) is
  _ignored_. These keys must also be Key Signing Keys (KSK). The **KEYFILE** must be the root name of the keys
  files, i.e if you have "Kmiek.nl.+013+26205.key", **KEYFILE** must be "Kmiek.nl.+013+26205". For finding the
  keys files the same rules apply as for **FILE**.
- **DIRECTORY** specifies where to write the signed zone files. If not specified the directory where **FILE**
  is found is used. If the path is relative, _root_ will be prepended.

## Examples

Sign the `example.org` zone contained in the file `db.example.org` and write the result to
`./db.example.org.signed` to let the _dbfile_ handler pick it up and serve it. The keys used
are read from `Kexample.org.+013+32412.key` and `Kexample.org.+013+32412.private`.

```txt
example.org {
    dbfile db.example.org.signed

    sign db.example.org {
        key Kexample.org.+013+32412
    }
}
```

Running this leads to the following log output (note the timers in this example have been set to
shorter intervals).

```txt

```

Forcibly resigning a zone can be accomplished by removing the signed zone file (testserv will keep
on serving it from memory), and `touch`-ing **FILE**.

## See Also

The DNSSEC RFCs: RFC 4033, RFC 4034 and RFC 4035. And the best current practice (BCP) on DNSSEC, RFC 6781. And
the _dbfile_ handler's documentation. Useful DNS(SEC) tools can be found in
[ldns](https://nlnetlabs.nl/projects/ldns/about/), e.g. `ldns-key2ds` to create DS records from DNSKEYs.

# sign

## Name

_sign_ - add DNSSEC records to zone files

## Description

The _sign_ handler is used to (DNSSEC) sign zones. In this process DNSSEC resource records are
added. The signatures that sign the resource records sets have an expiration date, this means the
signing process must be repeated before this expiration data is reached. Otherwise the zone's data
will go BAD (RFC 4035, Section 5.5). The _sign_ plugin takes care of this.

Only NSEC is supported, _sign_ does _not_ support NSEC3.

_Sign_ works in conjunction with the _file_ plugin; this plugin **signs** the zone's files, and
_file_ **serves** the zone's _data_.

For this plugin to work at least one Common Signing Key is needed. This key
(or keys) will be used to sign the entire zone. _Sign_ does _not_ support the ZSK/KSK split, nor will it do
key or algorithm rollovers - it just signs.

_sign_ will:

- (Re)-sign the zone with the CSK(s) when:

  - the last time it was signed is more than a 6 days ago. Each zone will have some jitter
    applied to the inception date.
  - the signature only has 14 days left before expiring.

  Both dates are only checked on the SOA's signature(s).

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

There are two ways that dictate when a zone is signed. Normally every 6 days (plus jitter) it will
be resigned. If for some reason we fail this check, the 14 days before expiring kicks in.

The state of each zone will be checked at 5 our intervals. The modification time is checked every 5
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
    key FILE [FILE...]
}
```

- **FILE** the zone database file to read and parse. If the path is relative, the path from the
  _root_ plugin will be prepended to it.
- `key` specifies the key(s) (there can be multiple) to sign the zone.
  Any metadata in these files (Activate, Publish, etc.) is
  _ignored_. These keys must also be Key Signing Keys (KSK).

## Examples

Sign the `example.org` zone contained in the file `db.example.org` and write the result to
`./db.example.org.signed` to let the _file_ plugin pick it up and serve it. The keys used
are read from `/etc/coredns/keys/Kexample.org.key` and `/etc/coredns/keys/Kexample.org.private`.

```txt
example.org {
    dbfile db.example.org.signed

    sign db.example.org {
        key Kexample.org
    }
}
```

Running this leads to the following log output (note the timers in this example have been set to
shorter intervals).

```txt
[WARNING] plugin/file: Failed to open "open /tmp/db.example.org.signed: no such file or directory": trying again in 1m0s
[INFO] plugin/sign: Signing "example.org." because open /tmp/db.example.org.signed: no such file or directory
[INFO] plugin/sign: Successfully signed zone "example.org." in "/tmp/db.example.org.signed" with key tags "59725" and 1564766865 SOA serial, elapsed 9.357933ms, next: 2019-08-02T22:27:45.270Z
[INFO] plugin/file: Successfully reloaded zone "example.org." in "/tmp/db.example.org.signed" with serial 1564766865
```

Or use a single zone file for _multiple_ zones, note that the **ZONES** are repeated for both plugins.
Also note this outputs _multiple_ signed output files. Here we use the default output directory
`/var/lib/coredns`.

```txt
. {
    file /var/lib/coredns/db.example.org.signed example.org
    file /var/lib/coredns/db.example.net.signed example.net
    sign db.example.org example.org example.net {
        key directory /etc/coredns/keys
    }
}
```

This is the same configuration, but the zones are put in the server block, but note that you still
need to specify what file is served for what zone in the _file_ plugin:

```txt
example.org example.net {
    file var/lib/coredns/db.example.org.signed example.org
    file var/lib/coredns/db.example.net.signed example.net
    sign db.example.org {
        key directory /etc/coredns/keys
    }
}
```

Be careful to fully list the origins you want to sign, if you don't:

```txt
example.org example.net {
    sign plugin/sign/testdata/db.example.org miek.org {
        key file /etc/coredns/keys/Kexample.org
    }
}
```

This will lead to `db.example.org` be signed _twice_, as this entire section is parsed twice because
you have specified the origins `example.org` and `example.net` in the server block.

Forcibly resigning a zone can be accomplished by removing the signed zone file (CoreDNS will keep
on serving it from memory), and sending SIGUSR1 to the process to make it reload and resign the zone
file.

## See Also

The DNSSEC RFCs: RFC 4033, RFC 4034 and RFC 4035. And the BCP on DNSSEC, RFC 6781. Further more the
manual pages coredns-keygen(1) and dnssec-keygen(8). And the _file_ plugin's documentation.

Coredns-keygen can be found at
[https://github.com/coredns/coredns-utils](https://github.com/coredns/coredns-utils) in the
coredns-keygen directory.

Other useful DNSSEC tools can be found in [ldns](https://nlnetlabs.nl/projects/ldns/about/), e.g.
`ldns-key2ds` to create DS records from DNSKEYs.

## Bugs

`keys directory` is not implemented.

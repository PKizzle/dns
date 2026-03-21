# Name

_uncloud_ - power Uncloud dynamic registrations

# Description

The _uncloud_ handler implements the web API of [uncloud-dns](https://github.com/psviderski/uncloud-dns).

It uses a SQLite database to persist these records. The database used is compatible with the _dbsqlite_
handler, and in fact to serve records from the database you must also enable the _dbsqlite_ handler. The
_uncloud_ handler assumes full ownership of the database and will purge old records (after 30 days), even if
they are not written by this handler.

If the global config contains a `tls` section those certificates are used for the server, and a TLS server is
started.

The _uncloud_ handler can only have a single zone, multiple zones will lead to an error.

# Syntax

```
uncloud DATABASE {
    addr ADDRESS
}
```

- **DATABASE** the SQLite database to use. If the path is relative, the path from the global root path will be
  prepended to it. This must be the same database as _dbsqlite_ will use.
- with `addr` you specify where the **ADDRESS** of the server. It defaults to `[::]:443` even without TLS.

If **DATABASE** does not exists and error is returned.

# Examples

Allow registrations and queries for `uncloud.example.org` and `uncl.example.net`.

```conffile
uncld.example.org {
    dbsqlite uncl.db
    uncloud uncl.db
}
```

# Also See

See <https://github.com/psviderski/uncloud-dns>, [AcornDNS](https://github.com/acorn-io/acorn-dns),
as this is a reimplementation of it.

# dbsqlite

## Name

_dbsqilte_ - serve zone data from a SQLite database

## Description

The _dbsqlite_ handler reads zone data from a data and serves that to clients. If the database contains
signatures (i.e. is signed using DNSSEC), correct DNSSEC answers are returned. Only NSEC is suppored.

The _sign_ handler does _not_ support databases, so you need something like ldns-signzone to sign and resign
your zones and put the generated records in the datebase. The database needs a custom collation, which means
it can not be created off-line. When started the database file will be created and the schema will be written
to it (if it does not already exist). After this step, the handler will never write to the database, for the
purpose of generating answers the database is completely read-only.

An RR that fails to be converted into a propper `dns.RR` is silently discarded, unless `debug` is active, see
atomdns-global(7) for details. The class is `IN` and can't be overriden.

The server will reply with minimal responses by default.

The schema used is:

```sql
CREATE TABLE rrs (
name VARCHAR(255),
type VARCHAR(10),
data VARCHAR(65535),
ttl INTEGER,
UNIQUE (name, type, data)
);
```

You can just add RRs to this table for _any_ zone and _dbsqlite_ will happily use them. Relative names will be
made not be made into fully qualified ones, and for some queries that will not be matched and silently _not_ included.

    sqlite> insert into rrs values ( '_ssh._tcp.host1.example.', 'srv', '10 5 43 example', 3600);
    sqlite> insert into rrs values ( 'subdel.example', 'ns', 'ns.example.com', 3600);

This one database can be savely used for all zones you have. Note that you still have to make sure the handler
gets queries for new zones.

## Syntax

In it simplests form _dbsqlite_ you can use:

```
dbsqlite DATABASE
```

- **DATABASE** the file the sqlite database to query. If the path is relative, the path from the global root config will be
  prepended to it.

If **DATABASE** does not exists the file is created and the `rrs` table is initialized.

For extra control you can open the block and define multipe extra properties that deal with zone transfers. Only outgoing zone
transfers are supported.
It is similar to _dbfile_, and we refer to that documentation then to repeat it here.

```
dbsqlite DATABASE {
    transfer {
        to [IP[:PORT]]... {
            notify IP[:PORT] [IP[:PORT]]...
            source IP [IP]...
            key NAME ALGORITHM SECRET
        }
    }
}
```

## Examples

Have both `example.org` and `example.net` read from the same database.

```conffile
example.org example.net {
    dbsqlite example.db
}
```

If you want _everything_ to end up in _dbsqlite_, you might be tempted to:

```conffile
. {
    dbsqlite root.db
}
```

But this fails, _unless_ you are actually authoritative for `.` (the root zone), this because the origins are
used to find those origins in the database.

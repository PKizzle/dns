# dbsqlite

## Name

_dbsqilte_ - serve zone data from a SQLite database

## Description

The _dbsqlite_ handler reads zone data from a data and serves that to clients. If the database contains
signatures (i.e. is signed using DNSSEC), correct DNSSEC answers are returned. Only NSEC is suppored.
The _sign_ handler does _not_ support databases, so you need something like ldns-signzone to sign and resign
your zones and put the generated records in the datebase. The database needs a custom collation, which means
it can not be created off-line.

The server will reply with minimal responses by default.

The schema used is:

```sql
CREATE TABLE rrs (
name VARCHAR(255) COLLATE canonical,
type VARCHAR(10),
data VARCHAR(65535),
ttl INTEGER DEFAULT 3600,
UNIQUE (name, type, data),
);
```

You can just add RRs to this table for any domain and _dbsqlite_ will happily use them. Relative names will be
made into fully qualified ones, by just adding the closing dot, no origin is appended.

    sqlite> insert into rrs values ( '_ssh._tcp.host1.example.', 'srv', '10 5 43 example');
    sqlite> insert into rrs values ( 'subdel.example', 'ns', 'ns.example.com');

## Syntax

In it simplests form \_dbsqlite you can use:

```
dbsqlite DATABASE
```

- **DATABASE** the file the sqlite database to query. If the path is relative, the path from the global root config will be
  prepended to it.

If **DATABASE** does not exists the file is created and the `rrs` table is initialized.

For extra control you can open the block and define multipe extra properties that deal with zone transfers.
This is similar to _dbfile_, and we refer to that documentation then to repeat it here.

```
dbsqlite DATABASE {
    transfer {
        from IP[:PORT] [IP[:PORT]]... {
            key NAME ALGORITHM SECRET
        }
        to [IP[:PORT]]... {
            notify IP[:PORT] [IP[:PORT]]...
            source IP [IP]...
            key NAME ALGORITHM SECRET
        }
    }
}
```

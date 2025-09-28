# store

## Name

_store_ - store DNS responses

## Description

With _store_ you cache messages for faster retrieval. The responses code on responses will be checked as
_store_ will only cache RcodeNameError and RcodeSuccess.

## Syntax

```
store
```

## Examples

The _dbsqlite_ handler needs round trips to the database which slows things down, to make it faster you can
deploy the cache in front of it:

```conffile
example.org {
    store
    dbsqlite example.org.db
}
```

## Design

The _store_ caches nodes that are build up as follows, in brackets are the Go types:

```
Name     [string]
Rcode    [uint16
Time     [time.Time]
Answer   [[]dns.RR]
Ns       [[]dns.RR]
Extra    [[]dns.RR]
```

From bottom to top. Answer, Ns, and Extra contains the read-only part of the message. These can be copied
as-is and don't need to be deep copied out of the cache. Time is the timestamp of when this partical node was
added, this is used for purging the store. Rcode is the response code of the message, only RcodeNameError is
of importance here, if such a node is found, there can't be anything below that name. Name is the name of the
node, this was the original query that lead to this reponse being cached.

# store

## Name

_store_ - store dns messages

## Description

With _store_ you cache messages for faster retrieval.

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
Msg      [*dns.Msg]
```

From bottom to top. Msg contains the read-only part of a dns message, those are the RRs in the answer,
authority and additional section. These can be copied as-is and don't need to be deep copied out of the cache.
The header section of Msg is only here because it easier to leave it in, then to strip it.
Time is the timestamp of when this partical node was added, this is used for purging the store. Rcode
is the response code of the message, only RcodeNameError is of importance here, if such a node is found, there
can't be anything below that name. Name is the canonicalized name of the node, this was the original query
that lead to this reponse.

The cache it self is a binary tree implementation that is also used in _dbfile_.

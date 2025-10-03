# Name

_msgcache_ - cache DNS messages

# Description

With _msgcache_ messages are cached for faster retrieval. The responses code on responses will be checked as
_msgcache_ will only cache RcodeNameError and RcodeSuccess. Items will be cached for a minimum of 600 seconds (5
minutes), or their actual TTL with a maximum of a week (604800 seconds). After that they are evicted from the
cache. For each cached elements a random jitter of up to 2 hours is added.

# Syntax

```
msgcache
```

# Examples

The _dbsqlite_ handler needs round trips to the database which slows things down, to make it faster you can
deploy the cache in front of it:

```conffile
example.org {
    msgcache
    dbsqlite example.org.db
}
```

# Bugs

This handler is not deemed ready yet.

# Design

The _msgcache_ caches nodes that are build up as follows, in brackets are the Go types:

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
added, this is used for purging the msgcache. Rcode is the response code of the message, only RcodeNameError is
of importance here, if such a node is found, there can't be anything below that name. Name is the name of the
node, this was the original query that lead to this reponse being cached.

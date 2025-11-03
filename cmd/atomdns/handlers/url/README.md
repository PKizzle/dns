# Name

_url_ - serve zone data from an URL

# Description

The _url_ handler is used for serving zone data that is fetched from an URL. The most prominent example of
this is downloading the root zone from <https://www.internic.net/domain/root.zone>.

The server will reply with minimal responses by default. The _url_ handler will watch the zone file and when
it receives a (kernel) notify it will reload the zone after 2 seconds.

# Syntax

```
url URL FILE
```

- **URL** the URL to fetch the zone from, if the scheme is omitted `https://` is assumed.
- **FILE** the zone file to save the data to and to serve from. If the path is relative, the path from the
  global root config will be prepended to it.

If the origins specification contains multiple origins, they all will use the _same_ **FILE**. And you must make
sure that zone **FILE** is generic enough, i.e. use `@` for origins instead of domain names.

# Examples

Load the root zone from and save it in `_.transferred`.

```conffile
. {
    url www.internic.net/domain/root.zone _.transferred
}
```

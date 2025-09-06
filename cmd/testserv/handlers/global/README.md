# global

## Name

_global_ - hold global server properties

## Description

_global_ holds global server properties, like the prometheus metrics port and root directory.
It only implements the `Setupper` interface and it's a handler.

## Syntax

```txt
root DIRECTORY
prometheus ADDRRES
```

- **DIRECTORY** is the directory to use as the root directory for the server. Any relative path names will
  get this directory prefixed.
- The _prometheus_ property allows setting the listening **ADDRESS**.

## Examples

```conffile
{
    root /var/lib/testserv
}
```

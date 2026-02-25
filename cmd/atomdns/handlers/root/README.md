## Name

_root_ - override the global root

# Description

Usually the global section has a `root` directive. This handler allows you to override it for each handler
block if desired. It works identical to the atomdns-global(1) root's configuration.

# Syntax

```txt
root DIRECTORY
```

- with `root` **DIRECTORY** is the directory to use as the root directory for the server. Any relative path
  names will get this directory prefixed. If **DIRECTORY** itself is also relative the current working
  directory (cwd) of the atomdns process will be prefixed.

# Notes

This handler must be set first in a handler block to effect all handlers in the block.

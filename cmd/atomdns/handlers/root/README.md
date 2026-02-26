## Name

_root_ - override the global root

# Description

This handler allows for overriding the `root` directive from the global section in the current handler block.
It works identical to the atomdns-global(1) `root`'s configuration.

# Syntax

```txt
root DIRECTORY
```

- with `root` **DIRECTORY** is the directory to use as the root directory in the handler block. Any relative path
  names will get this directory prefixed. If **DIRECTORY** itself is also relative, the current working
  directory (cwd) of the atomdns process will be prefixed.

# Notes

This handler must be set first in a handler block to effect all subsequent handlers in the block.

# Also See

atomdns-global(1).

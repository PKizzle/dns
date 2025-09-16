## sndns

*sndns* - pluggable DNS nameserver.

## Synopsis

*sndns* **[-conf FILE]** **[-p PORT}** **[OPTION]**...

## Description

sndns is a DNS server that chains plugins. Each plugin handles a DNS feature, like server zones
other transfering those to secondaries or just exporting metrics. There are many other plugins, each
described in their respective manual pages. See the "See Also" section for a list.

When started without options sndns will look for a file named `Corefile` in the current
directory, if found, it will parse its contents and start up accordingly. If no `Corefile` is found
it will start with the *whoami* plugin (sndns-whoami(7)) and start listening on port 53 (unless
overridden with `-p`).

Available options:

**-conf** **FILE**
: specify Corefile to load, if not given sndns will look for a `Corefile` in the current
  directory.

**-p** **PORT**
: override default port (53) to listen on.

**-pidfile** **FILE**
: write PID to **FILE**.

**-plugins**
: list all plugins and quit.

**-quiet**
: don't print any version and port information on startup.

**-version**
: show version and quit.

## Authors

CoreDNS and sndns Authors.

## Copyright

Apache License 2.0

## See Also

Corefile(5) @@PLUGINS@@.

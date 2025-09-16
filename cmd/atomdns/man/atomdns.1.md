## atomdns

_atomdns_ - DNS nameserver that runs handlers

## Synopsis

_atomdns_ **[-c FILE]** **[-p PORT]** **[OPTION]**...

## Description

atomdns is a DNS server that chains handlers. Each handler handles a DNS feature, like serve zone files,
transfering those to secondaries or just exporting metrics. There are many handlers, each described in their
respective manual pages.

Available options:

**-c**, **-conf** **FILE**
: specify Corefile to load, if not given atomdns will look for a `Conffile` in the current
directory.

**-p**, **--port** **PORT**
: override default port (53) to listen on.

**-handlers**
: list all handlers and quit.

**-v**, **-version**
: show version and quit.

**-cpuprofile**
: write a cpu profile to "cpu.out".

## Authors

atomdns authors.

## Copyright

Apache License 2.0

## See Also

See Conffile(5)

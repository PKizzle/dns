# Handlers

## Query Processing

Once CoreDNS has been started and has parsed the configuration, it runs Servers. Each Server is defined by the zones it serves and on what port. Each Server has its own Plugin Chain.

When a query is being processed by CoreDNS, the following steps are performed:

    If there are multiple Servers configured that listen on the queried port, it will check which one has the most specific zone for this query (longest suffix match). E.g. if there are two Servers, one for example.org and one for a.example.org, and the query is for www.a.example.org, it will be routed to the latter.

    Once a Server has been found, it will be routed through the Plugin Chain that is configured for this server. This always happens in the same order. That (static) ordering is defined in plugin.cfg.

    Each plugin will inspect the query and determine if it should process it (some plugins allow you to filter further on the query name or other attributes). A couple of things can now happen:
        The query is processed by this plugin.
        The query is not processed by this plugin.
        The query is processed by this plugin, but half way through it decides it still wants to call the next plugin in the chain. We call this fallthrough after the keyword that enables it.
        The query is processed by this plugin, a “hint” is added and the next plugin is called. This hint provides a way to “see” the (eventual) response and act upon that.

Processing a query means a Plugin will respond to the client with a reply.

Note that a plugin is free to deviate from the above list as it wishes. Currently, all plugins that come with CoreDNS fall into one of these four groups though. Note this blog post also provides background in the query routing.
Query is Processed

The plugin processes the query. It looks up (or generates, or whatever the plugin author decided this plugin does) a response and sends it back to the client. The query processing stops here, no next plugin is called. A (simple) plugin that works like this is whoami.
Query is Not Processed

If the plugin decides it will not process a query, it simply calls the next plugin in the chain. If the last plugin in the chain decides to not process the query, CoreDNS will return SERVFAIL back to the client.
Query is Processed With Fallthrough

In this situation, a plugin handles the query, but the reply it got from its backend (i.e. maybe it got NXDOMAIN) is such that it wants other plugins in the chain to take a look as well. If fallthrough is provided (and enabled!), the next plugin is called. A plugin that works like this is the hosts plugin. First, a lookup in the host table (/etc/hosts) is attempted, if it finds an answer, it returns that. If not, it will fallthrough to the next one in the hope that other plugins may return something to the client.
Query is Processed With a Hint

A plugin of this kind will process a query, and will always call the next plugin. However, it provides a hint that allows it to see the response that will be written to the client. A plugin that does this is prometheus. It times the duration (among other things), but doesn’t actually do anything with the DNS request - it only passes it on and inspects some meta data on the return path.

## Add a New Handler

The plugin.md in the CoreDNS source tree has some pointers on what a plugin for CoreDNS should have as minimum requirements. It basically boils down to: “it should add something unique and useful to CoreDNS”. Further more documentation, tests and functionality should all be excellent.

It is easier to list when a plugin can be included in CoreDNS than to say it should stay external, so we will do that:

    First, the plugin should be useful for other people. “Useful” is a subjective term, but the plugin needs to fill a niche that appeals to more than one person.
    It should be sufficiently different from other plugins to warrant inclusion.
    Current internet standards need be supported: IPv4 and IPv6, so A and AAAA records should be handled (if your plugin is in the business of dealing with address records that is).
    It must have tests.
    It must have a README.md for documentation.
    Care must be taken to make it efficient in both memory and CPU.

Plugins for CoreDNS can easily live out-of-tree, plugin.cfg defaults to CoreDNS' repo but other repos work just as well.

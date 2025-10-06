# Name

_catalog_ - handle catalog zones

# Description

Catalog zones (RFC 9432) are meta DNS zones that carry information on how to provision zones, _catalog_
(likely) needs a `transfer` section so it knows how to get a) the catalog zone itself and b) all zones
_mentioned_ in the catalog.

# Syntax

In it simplests form _catalog_ you can use:

```
catalog FILE
```

- **FILE** the zone file to load. If the path is relative, the path from the global root config will be
  prepended to it.

All zones that are mentioned in the catalog zone are transferred

To allow more control the following extra options are available.

```
catalog FILE {
    snippet SNIPPET
    group GROUP [GROUP]... {
        snippet SNIPPET
    }
    transfer {
        from IP[:PORT] [IP[:PORT]]... {
            key NAME ALGORITHM SECRET
        }
    }
}
```

- `snippet` tells with **SNIPPET** must be used for when this zone is added, i.e. if it is "catalog", the
  configuration could contain:

  ```
  (catalog) {
        log
        metrics
  }
  ```

  The new zone will be put as last in the handler chain with _log_ and _metrics_ before it, and with _refuse_
  as the backstop.

- With `group` you can potentially wrap the configuration in a group clause, which will apply it only for
  zones that are grouped in those **GROUP**s in the catalog zone.
- The `transfer` section holds the configuration for getting the zone from a primary.

# Examples

Here we define a `catalog.invalid` zone with _catalog_ that retrieves the zone. The _catalog_ handler will not
serve this zone, but will use it to transfer the mentioned zones in and apply the snippets on the per group
basis if needed, otherwise the non-group snippet applies.

```conffile
catalog.invalid {
    catalog catalog.invalid.catalog {
        group groupa {
            snippet catalog-groupa
        }
        snippet catalog
        transfer {
            from 10.10.10.1
        }
    }
}

(catalog-groupa) {
    metrics
}

(catalog) {
    log
    metrics
}
```

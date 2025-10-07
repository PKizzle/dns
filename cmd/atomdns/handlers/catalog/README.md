# Name

_catalog_ - process catalog zones

# Description

Catalog zones (RFC 9432) are meta DNS zones that carry information on how to provision zones, _catalog_
uses zone transfers to get a) the catalog zone itself and b) all zones _mentioned_ in the catalog.

# Syntax

In it simplests form _catalog_ you can use:

```
catalog FILE
```

- **FILE** the catalog zone file to load. If the path is relative, the path from the global root config will be
  prepended to it.

However this is fairly minimal, and only loads the catalog zone, To allow more control the following extra
options are available.

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

  The new zone will be put as last in the handler chain with _log_ and _metrics_ before it, then _dbfile_ with
  the tranferered zone and then _refuse_ as the backstop. The default without `snippet` is just, _dbfile_.

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

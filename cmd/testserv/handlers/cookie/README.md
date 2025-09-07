# nsid

## Name

_cookie_ - adds an DNS cookie of this server to each reply

## Description

This plugin implements the DNS cookie RFC.

## Syntax

```txt
cookie SECRET
```

Where **SECRET** is the secret to use in the server cookie generation record.

## Examples

Enable nsid:

```corefile
example.org {
    whoami
    cookie Use the force
}
```

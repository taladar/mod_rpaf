# mod_rpaf behaviour matrix

A podman harness that builds the module from a source tree, runs it in a real
Apache and prints a normalised transcript of what the backend ends up seeing.
Its purpose is to let a change be diffed against the previous revision **before**
the module is packaged and rolled out, since this module sits in front of every
request on every host that uses it.

## Usage

    ./capture.sh <src-dir> <outdir> [--with-forwarded] [base-image]

`<src-dir>` is a mod_rpaf working tree or export. The result is one transcript per
configuration in `<outdir>`, plus the build log. Pass `--with-forwarded` only for a
tree that knows `RPAF_EnableForwarded`; an older module aborts at config parse time
on the unknown directive.

Typical run when changing the module:

    git archive HEAD | (mkdir -p /tmp/rpaf-head && tar -x -C /tmp/rpaf-head)
    ./capture.sh /tmp/rpaf-head out-baseline
    ./capture.sh .. out-modified --with-forwarded

    # the configurations that do not use the new directives must not change at all
    for c in trusted untrusted trusted-clean untrusted-clean untrusted-forbid; do
      diff -u out-baseline/$c.txt out-modified/$c.txt
    done

    # and then read the new behaviour
    less out-modified/trusted-forwarded.txt out-modified/untrusted-forwarded.txt

Other Debian releases, to confirm the packaging targets still compile:

    ./capture.sh .. out-trixie    --with-forwarded debian:trixie
    ./capture.sh .. out-bullseye  --with-forwarded debian:bullseye

## How trusted and untrusted are simulated

All requests are made from inside the container, so the peer is always loopback.
Which branch of the module they take is decided by the config, not by the network:

* default: `RPAF_ProxyIPs 127.0.0.1 ::1`, so the peer **is** a trusted proxy
* `-D UNTRUSTED`: `RPAF_ProxyIPs 192.0.2.1`, so the peer is **not**

That keeps the harness independent of podman's rootless network topology, where a
connection from the host can appear to come from loopback anyway.

`-D CLEANHEADERS`, `-D FORBID` and `-D FORWARDED` switch on `RPAF_CleanHeaders`,
`RPAF_ForbidIfNotProxy` and `RPAF_EnableForwarded` + `RPAF_SanitizeHeaders`.

## mod_ssl

Most servers this module runs on sit behind nginx or varnish on plain http and do
not load mod_ssl at all, so that is the default here. `-D SSLVHOST` loads mod_ssl
and adds a TLS terminating vhost on 443, which is the only way to exercise the
`ssl_is_https` branch of the `proto` parameter: at `post_read_request` neither the
`rpaf_https` connection note nor mod_ssl's `HTTPS` environment variable exists yet
(mod_ssl sets that in its fixup hook), so a request with no `X-Forwarded-*` headers
at all reporting `proto=https` can only have got that from `ssl_is_https`.

Without mod_ssl, `APR_RETRIEVE_OPTIONAL_FN(ssl_is_https)` resolves to this module's
own implementation, which reports the `rpaf_https` note, so `proto` then reflects
purely what `RPAF_SetHTTPS` derived from the upstream headers. That is the correct
answer for a server that has no TLS of its own.

## Notes

* The endpoint is a CGI script that dumps the request-relevant environment, so one
  request shows `REMOTE_ADDR`, `SERVER_NAME`, `SERVER_PORT`, `HTTPS`, `REMOTE_USER`,
  `X_REQUEST_ID` and every interesting `HTTP_*` at once.
* `single-worker.conf` pins Apache to one prefork child. The module assigns
  `r->server->server_scheme` per request on a structure shared by the whole server
  (see the comments at the top of `mod_rpaf.c`), so with several children a request
  can inherit the scheme of an unrelated earlier request and the transcript becomes
  nondeterministic. One child makes that pre-existing effect deterministic and
  therefore diffable.
* Request ids embed a connection id and a timestamp and are normalised to
  `apache-<GENERATED>`.
* `000-test.conf` reproduces the `SetEnvIf X-Forwarded-User ^(.*)$ REMOTE_USER=$1`
  pattern used by header-based authentication behind an authenticating proxy, which
  is what `RPAF_SanitizeHeaders` has to protect.

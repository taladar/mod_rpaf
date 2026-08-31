## mod_rpaf - reverse proxy add forward

### Summary

Sets `REMOTE_ADDR`, `HTTPS`, and `HTTP_PORT` to the values provided by an upstream proxy.
Sets `remoteip-proxy-ip-list` field in r->notes table to list of proxy intermediaries.


### Compile Debian/Ubuntu Package and Install

    sudo apt-get install build-essential apache2-threaded-dev yada
    make
    make install   

### Compile and Install for RedHat/CentOS

    yum install httpd-devel
    make
    make install

### Configuration Directives

    RPAF_Enable             (On|Off)                - Enable reverse proxy add forward

    RPAF_ProxyIPs           127.0.0.1 10.0.0.0/24   - What IPs & bitmaksed subnets to adjust
                                                      requests for

    RPAF_Header             X-Forwarded-For         - The header to use for the real IP 
                                                      address.

    RPAF_SetHostName        (On|Off)                - Update vhost name so ServerName &
                                                      ServerAlias work

    RPAF_SetHTTPS           (On|Off)                - Set the HTTPS environment variable
                                                      to the header value contained in
                                                      X-HTTPS, or X-Forwarded-HTTPS. For
                                                      best results make sure that mod_ssl
                                                      is NOT enabled.

    RPAF_SetPort            (On|Off)                - Set the server port to the header
                                                      value contained in X-Port, or
                                                      X-Forwarded-Port. (See Issue #12)

    RPAF_CleanHeaders       (On|Off)                - Cleanup the headers added/altered by
                                                      the reverse proxy to hide it from the
                                                      client application.

    RPAF_ForbidIfNotProxy   (On|Off)                - Option to forbid request if not from
                                                      trusted RPAF_ProxyIPs; otherwise
                                                      cannot be done with Allow/Deny after
                                                      remote addr substitution

    RPAF_EnableRequestId    (On|Off)                - Take the request id from the request
                                                      id header if the request comes from a
                                                      trusted RPAF_ProxyIPs, generate one
                                                      otherwise, and expose it as the
                                                      X_REQUEST_ID environment variable

    RPAF_RequestIdHeader    X-Request-Id            - The header to use for the request id

    RPAF_EnableForwarded    (On|Off)                - Maintain the RFC 7239 Forwarded
                                                      request header (see below)

    RPAF_SanitizeHeaders    X-Real-IP X-Forwarded-Host
                                                    - Request headers to remove unless the
                                                      request comes from a trusted
                                                      RPAF_ProxyIPs, for headers a reverse
                                                      proxy may legitimately set but a
                                                      client must never be able to inject


### RFC 7239 Forwarded support

`RPAF_EnableForwarded On` makes the module maintain the standard
[RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html) `Forwarded` request header
in addition to, not instead of, the `X-Forwarded-*` headers. Applications behind
the proxy can then evaluate the standard header and get a value they can trust:

* request **not** from a trusted `RPAF_ProxyIPs`: whatever the client sent is
  discarded and replaced by a single element describing that client
* request from a trusted `RPAF_ProxyIPs`: the value received is kept and one
  element for the hop to this server is appended, per RFC 7239 section 4

The element looks like `for=192.0.2.1;proto=https;host="www.example.com";by=198.51.100.7`,
with IPv6 node identifiers bracketed and quoted (`for="[2001:db8::1]"`) as required
by RFC 7239 section 6. `proto` reflects what `RPAF_SetHTTPS` derived from the
upstream headers, or a TLS connection terminated by this server.

`RPAF_SanitizeHeaders` is independent of `RPAF_EnableForwarded` and covers the
non-standard headers: anything listed there is removed from a request that did not
come from a trusted proxy. Because the module runs in `post_read_request` at
`APR_HOOK_REALLY_FIRST`, the headers are gone before `mod_setenvif` and friends
run, so a configuration that derives e.g. `REMOTE_USER` from an
`X-Forwarded-User` header set by an authenticating proxy cannot be fooled by a
client that sets the header itself.

## Example Configuration

    LoadModule              rpaf_module modules/mod_rpaf.so
    RPAF_Enable             On
    RPAF_ProxyIPs           127.0.0.1 10.0.0.0/24
    RPAF_SetHostName        On
    RPAF_SetHTTPS           On
    RPAF_SetPort            On
    RPAF_ForbidIfNotProxy   Off
    RPAF_EnableForwarded    On
    RPAF_SanitizeHeaders    X-Forwarded-Host X-Forwarded-Server X-Forwarded-Ssl X-Real-IP
    RPAF_SanitizeHeaders    X-Forwarded-User X-Forwarded-Email X-Forwarded-Groups

## Tests

`test/` holds a podman harness that runs a behaviour matrix against a real Apache
and prints a normalised transcript, so a change can be diffed against the previous
revision before it is packaged. See `test/README.md`.

## Authors

* Thomas Eibner <thomas@stderr.net>
* Geoffrey McRae <gnif@xbmc.org>
* Proxigence Inc. <support@proxigence.com>

## License and distribution

This software is licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0). The
latest version is available [from GitHub](http://github.com/gnif/mod_rpaf)

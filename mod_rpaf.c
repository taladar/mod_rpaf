/*
   Copyright 2011 Ask Bjørn Hansen

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Apache 2.4.19+ and 2.5

// ===== List of C-value to user visible values mapping
// === in modules/http/http_core.c
// in http_scheme (fallback for ap_http_scheme if not other module overwrites it)
//
// uses r->server->server_scheme to determine whether it should return https or http
//
// in http_port (fallback for ap_default_port if no other module overwrites it)
//
// uses r->server->server_scheme to determine default port to return
//
// === in server/vhost.c
//
// in ap_update_vhost_given_ip
//
// uses r->connection->local_addr
//   on exact match sets r->connection->vhost_lookup_data
//   on exact match sets r->connection->base_server
// uses r->connection->local_addr->port
//   does same as above if default server exists for this port
// if neither exact match nor default server exists set r->connection->vhost_lookup_data to NULL
//
// in ap_update_vhost_from_headers
//
// uses r->headers_in table key Host
// uses r->hostname over above and updates r->headers_in table key Host in that case based on r->hostname and r->parsed_uri.port_str
// if r->connection->vhost_lookup_data is non-NULL
//   if r->hostname is set
//     calls check_hostalias(r)
//   else
//     calls check_serverpath(r)
//
// in check_hostalias
// comment claims that it always uses the physical part, never one from Host header or other sources
// uses r->hostname
// uses r->connection->local_addr->port
// traverses r->connection->vhost_lookup_data
// if it finds a matching entry (host and port)
//   sets r->server to the server field from the entry (no copy which confirms that we should never update r->server)
//
// in check_serverpath (only used for requests without a Host header)
// uses r->connection->local_addr->port
// uses r->uri to compare it to ServerPath setting
//
// === in server/core.c in httpd source
//
// in ap_get_useragent_host
// if r->useragent_addr is unset or identical to r->connection->client_addr
//   return result of ap_get_remote_host
// if hostname lookups are on and r->useragent_host is unset
//   DNS lookup r->useragent_addr to set r->useragent_host
//   some weird double reverse lookup logic
//   if DNS lookup fails sets r->useragent_host to empty string to indicate error
// if r->useragent_host is not NULL and not the empty string
//   return r->useragent_host
// else
//   if parameter was REMOTE_HOST or REMOTE_DOUBLE_REV return NULL
//   else return r->useragent_ip
//
// in ap_get_remote_host
// does essentially the same thing as ap_get_useragent_host only without
// the initial check to call this function and with
// r->remote_host instead of r_useragent_host and
// r->connection->client_addr instead of r->useragent_addr and
// r->client_ip instead of r->useragent_ip
//
// in ap_get_server_port
//   if CanonicalName is off, DNS or unset
//     if CanonicalPhysicalPort is on
//       if r->parsed_uri->port_str is set
//         return r->parsed_uri->port
//       else
//         if r->connection->local_addr->port is set
//           return r->connection->local_addr->port
//         else
//           if r->server->port is set
//             return r->server->port
//           else
//             return ap_default_port(r)
//     else
//       if r->parsed_uri->port_str is set
//         return r->parsed_uri->port
//       else
//         if r->server->port is set
//           return r->server->port
//         else
//           return ap_default_port(r)
//   else
//     if CanonicalPhysicalPort is on
//       if r->connection->local_addr->port is set
//         return r->connection->local_addr->port
//       else
//         if r->server->port is set
//           return r->server->port
//         else
//           return ap_default_port(r)
//     else
//       if r->server->port is set
//         return r->server->port
//       else
//         return ap_default_port(r)
//
// === in server/util_script.c in ap_add_common_vars in httpd source
// SERVER_ADDR request_rec->connection->local_ip
// SERVER_PORT ap_get_server_port(request_rec)
// REMOTE_HOST ap_get_useragent_host(r, REMOTE_HOST, NULL)
// REMOTE_ADDR request_rec->useragent_ip
// REMOTE_PORT request_rec->connection->client_addr->port
// REQUEST_SCHEME ap_http_scheme(request_rec)
// === in modules/loggers/mod_log_config.c in log_pre_config in httpd source
// (note, the a parameter in the handler functions is the one in {} between % and the letter)
//
// %h  in LogFormat ap_get_useragent_host(r, REMOTE_HOST, NULL)
// %{c}h in LogFormat ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL);
//
// %a  in LogFormat request_rec->useragent_ip
// %{c}a in LogFormat request_rec->connection->client_ip
//
// %A in LogFormat request_rec->connection->local_ip
//
// %V in LogFormat with setting CanonicalHostName on  r->server->server_hostname
// %V in LogFormat with setting CanonicalHostName off r->hostname
// %V in LogFormat with setting CanonicalHostname dns complex DNS stuff involving conn->local_host somehow (code of ap_get_server_name in server/core.c)
//
// %v in LogFormat r->server->server_hostname
//
// %p or %{canonical}p in LogFormat r->server->port or ap_default_port(r) (default port for scheme)
// %{remote}p          in LogFormat r->user_agent_addr->port
// %{local}p           in LogFormat r->connection->local_addr->port
//
// %H in LogFormat r->protocol (this is just something like HTTP/1.1 so we are not concerned with it, just listed so we do not need to discover this twice)
//
// === in modules/loggers/mod_journald.c in httpd sources
// provides some variables
// REQUEST_HOSTNAME r->hostname
// REQUEST_USERAGENT_IP r->useragent_ip
//
// === in modules/aaa/mod_authz_host.c in httpd sourcec
// apparently this uses r->useragent_ip and r->useragent_addr
//
// === in modules/proxy/mod_proxy_http.c in httpd sources
// this does some weird fake request stuff with data that is really a response, not sure if this is relevant beyond not needing to discover this twice
//
// === in modules/proxy/proxy_util.c in httpd sources
// adds X-Forward-For, X-Forwarded-Host and X-Forwarded-Server headers to reverse proxy requests in ap_proxy_create_hdrbrgd
//
// X-Forwarded-For is filled based on existing header value and r->useragent_ip
// X-Forwarded-Host is set to value of existing X-Forwarded-Host header + value of Host header
// X-Forwarded-Server is set to value of existing header + value of r->server->server_hostname

// ==========

// Apache 2.4.18 and earlier
//
// r->useragent_host mentioned above does not exist yet in these yersions
//
// === in server/core.c in httpd source
// ap_get_useragent_host does not exist yet
//
// === in server/util_script.c in ap_add_common_vars in httpd source
// REMOTE_HOST ap_get_remote_host(r, REMOTE_HOST, NULL)

// === in modules/loggers/mod_log_config.c in log_pre_config in httpd source
// %h in LogFormat ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NAME, NULL);
// %{c}h does not exist yet

// ==========

// Notes on things I do not want to have to discover twice
//
// We do not need to call ap_update_vhost_given_ip since that only ever depends on the r->connection->local_addr and r->connection->local_addr->port
// and we do not change that

// r->parsed_uri.port_str should not include a colon (unlike the way it is set in gnif's fork of mod_rpaf)

// We need to call ap_update_vhost_from_headers if we update r->hostname or r->parsed_uri.port_str
// At least in theory, in practice in some situations we do not want to do that since it adds a port to the Host header even if the port is the default port for the scheme

#include "ap_release.h"
#include "ap_listen.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_vhost.h"
#include "apr_strings.h"

#include <ctype.h> // isspace
#include <arpa/inet.h>

module AP_MODULE_DECLARE_DATA rpaf_module;
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

typedef struct {
    int                enable;
    int                sethostname;
    int                sethttps;
    int                setport;
    const char         *headername;
    apr_array_header_t *proxy_ips;
    const char         *https_scheme;
    int                forbid_if_not_proxy;
    int                clean_headers;
} rpaf_server_cfg;

typedef struct {
    const char  *old_useragent_ip;
    apr_sockaddr_t old_useragent_addr;
    request_rec *r;
} rpaf_cleanup_rec;

static void *rpaf_create_server_cfg(apr_pool_t *p, server_rec *s) {
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)apr_pcalloc(p, sizeof(rpaf_server_cfg));
    if (!cfg)
        return NULL;

    cfg->proxy_ips = apr_array_make(p, 10, sizeof(apr_ipsubnet_t *));
    cfg->enable = 0;
    cfg->sethostname = 0;
    cfg->forbid_if_not_proxy = 0;
    cfg->clean_headers = 0;

    cfg->https_scheme = apr_pstrdup(p, "https");

    return (void *)cfg;
}

/* quick check for ipv4/6 likelihood; similar to Apache2.4 mod_remoteip check */
static int rpaf_looks_like_ip(const char *ip) {
    static const char ipv4_set[] = "0123456789./";
    static const char ipv6_set[] = "0123456789abcdef:/.";

    /* zero length value is not valid */
    if (!*ip)
      return 0;

    const char *ptr    = ip;

    /* determine if this could be a IPv6 or IPv4 address */
    if (strchr(ip, ':'))
    {
        while(*ptr && strchr(ipv6_set, *ptr) != NULL)
            ++ptr;
    }
    else
    {
        while(*ptr && strchr(ipv4_set, *ptr) != NULL)
            ++ptr;
    }

    return (*ptr == '\0');
}

static const char *rpaf_set_proxy_ip(cmd_parms *cmd, void *dummy, const char *proxy_ip) {
    char *ip, *mask;
    apr_ipsubnet_t **sub;
    apr_status_t rv;
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    if (rpaf_looks_like_ip(proxy_ip)) {
        ip = apr_pstrdup(cmd->temp_pool, proxy_ip);
        if (mask = ap_strchr(ip, '/')) {
            *mask++ = '\0';
        }
        sub = (apr_ipsubnet_t **)apr_array_push(cfg->proxy_ips);
        rv = apr_ipsubnet_create(sub, ip, mask, cmd->pool);

        if (rv != APR_SUCCESS) {
            char msgbuf[128];
            apr_strerror(rv, msgbuf, sizeof(msgbuf));
            return apr_pstrcat(cmd->pool, "mod_rpaf: Error parsing IP ", proxy_ip, " in ",
                               cmd->cmd->name, ". ", msgbuf, NULL);
        }
    }
    else
    {
      return apr_pstrcat(cmd->pool, "mod_rpaf: Error parsing IP \"", proxy_ip, "\" in ",
                         cmd->cmd->name, ". Failed basic parsing.", NULL);
    }

    return NULL;
}

static const char *rpaf_set_headername(cmd_parms *cmd, void *dummy, const char *headername) {
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    cfg->headername = headername;
    return NULL;
}

static const char *rpaf_enable(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    cfg->enable = flag;
    return NULL;
}

static const char *rpaf_set_forbid_if_not_proxy(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    cfg->forbid_if_not_proxy = flag;
    return NULL;
}

static const char *rpaf_set_clean_headers(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    cfg->clean_headers = flag;
    return NULL;
}

static const char *rpaf_sethostname(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    cfg->sethostname = flag;
    return NULL;
}

static const char *rpaf_sethttps(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    cfg->sethttps = flag;
    return NULL;
}

static const char *rpaf_setport(cmd_parms *cmd, void *dummy, int flag) {
    server_rec *s = cmd->server;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(s->module_config,
                                                                   &rpaf_module);

    cfg->setport = flag;
    return NULL;
}

static int is_in_array(apr_sockaddr_t *remote_addr, apr_array_header_t *proxy_ips) {
    int i;
    apr_ipsubnet_t **subs = (apr_ipsubnet_t **)proxy_ips->elts;

    for (i = 0; i < proxy_ips->nelts; i++) {
        if (apr_ipsubnet_test(subs[i], remote_addr)) {
            return 1;
        }
    }

    return 0;
}

// taken from mod_remoteip (prefix renamed)
static int rpaf_is_server_port(apr_port_t port) {
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
        if (lr->bind_addr && lr->bind_addr->port == port) {
            return 1;
        }
    }

    return 0;
}

static apr_status_t rpaf_cleanup(void *data) {
    rpaf_cleanup_rec *rcr = (rpaf_cleanup_rec *)data;
    rcr->r->useragent_ip = apr_pstrdup(rcr->r->connection->pool, rcr->old_useragent_ip);
    memcpy(rcr->r->useragent_addr, &rcr->old_useragent_addr, sizeof(apr_sockaddr_t));
    apr_table_unset(rcr->r->connection->notes, "rpaf_https");
    return APR_SUCCESS;
}

// finds the last element in forward_for which is not in proxy_ips and
// adds all elements after that as well as the client ip to proxy_list
// and sets that proxy_list as a "remoteip-proxy-ip-list" note on the
// request, returns the last IP in forwarded_for that is not in proxy list
// if it exists, otherwise the first proxy ip if any valid IPs exist in
// forwarded_for, otherwise NULL
static char *last_not_in_array(request_rec *r, apr_array_header_t *forwarded_for,
                               apr_array_header_t *proxy_ips) {
    apr_sockaddr_t *sa;
    apr_status_t rv;
    char **fwd_ips, *proxy_list;
    int i, earliest_legit_i = 0;

    proxy_list = apr_pstrdup(r->connection->pool, r->connection->client_ip);
    fwd_ips = (char **)forwarded_for->elts;

    for (i = (forwarded_for->nelts); i > 0; ) {
        i--;
        rv = apr_sockaddr_info_get(&sa, fwd_ips[i], APR_UNSPEC, 0, 0, r->pool);
        if (rv == APR_SUCCESS) {
            earliest_legit_i = i;
            if (!is_in_array(sa, proxy_ips))
                break;

            proxy_list = apr_pstrcat(r->pool, proxy_list, ", ", fwd_ips[i], NULL);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          "mod_rpaf: forwarded-for list entry of %s is not a valid IP", fwd_ips[i]);
        }
    }

    if (i > 0 || rv == APR_SUCCESS || earliest_legit_i) {
        /* remoteip-proxy-ip_list r->notes entry is forward compatible with Apache2.4 mod_remoteip*/
        apr_table_set(r->notes, "remoteip-proxy-ip-list", proxy_list);
        return fwd_ips[earliest_legit_i];
    }
    else {
        return NULL;
    }
}

// main entry point when mod_rpaf processes a request
static int rpaf_post_read_request(request_rec *r) {
    // fwdvalue is the value of the X-Forwarded-For header if present
    char *fwdvalue, *val, *mask, *last_val;
    int i;
    apr_port_t tmpport;
    apr_pool_t *tmppool;
    const char *header_ip = NULL, *header_host = NULL, *header_https = NULL, *header_port = NULL;
    rpaf_server_cfg *cfg = (rpaf_server_cfg *)ap_get_module_config(r->server->module_config,
                                                                   &rpaf_module);

    if (!cfg->enable)
        return DECLINED;

    // taken from mod_remoteip, prefix of function renamed
    /* mod_proxy creates outgoing connections - we don't want those */
    if (!rpaf_is_server_port(r->connection->local_addr->port)) {
        return DECLINED;
    }

    /* this overcomes an issue when mod_rewrite causes this to get called again
       and the environment value is lost for HTTPS. This is the only thing that
       is lost and we do not need to process any further after restoring the
       value. We use a per connection note here even though the value is per
       request because we delete it in cleanup again and this way we only need
       one note for our implementation of ssl_is_https and this */
    const char *rpaf_https = apr_table_get(r->connection->notes, "rpaf_https");
    if (rpaf_https) {
        apr_table_set(r->subprocess_env, "HTTPS", rpaf_https);
        return DECLINED;
    }

    /* check if the remote_addr is in the allowed proxy IP list */
    if (is_in_array(r->connection->client_addr, cfg->proxy_ips) != 1) {
        if (cfg->forbid_if_not_proxy)
            return HTTP_FORBIDDEN;
        return DECLINED;
    }

    /* TODO: We should not just assume that we should fallback to
       X-Forwarded-For if cfg->headername is unset as this could
       pose a security risk, keeping this for now to keep our
       behaviour consistant */
    header_ip = cfg->headername;
    if (header_ip)
      fwdvalue = (char *)apr_table_get(r->headers_in, header_ip);
    if (!header_ip || !fwdvalue)
    {
      header_ip = "X-Forwarded-For";
      fwdvalue  = (char *)apr_table_get(r->headers_in, header_ip);
    }

    /* if there was no forwarded for header then we dont do anything */
    if (!fwdvalue)
        return DECLINED;

    /* split up the list of forwarded IPs */
    apr_array_header_t *arr = apr_array_make(r->pool, 4, sizeof(char *));
    while ((val = strsep(&fwdvalue, ",")) != NULL) {
        /* strip leading and trailing whitespace */
        while(isspace(*val))
            ++val;
        for (i = strlen(val) - 1; i > 0 && isspace(val[i]); i--)
            val[i] = '\0';
        if (rpaf_looks_like_ip(val))
            *(char **)apr_array_push(arr) = apr_pstrdup(r->pool, val);
    }

    /* if there were no IPs, then there is nothing to do */
    if (apr_is_empty_array(arr))
        return DECLINED;

    /* get the last IP and check if it is in our list of proxies
       if there is no valid IP in X-Forwarded-For
       decline to process the request */
    if ((last_val = last_not_in_array(r, arr, cfg->proxy_ips)) == NULL)
        return DECLINED;

    /* if we are cleaning up the headers then we need to correct the forwarded IP list */
    if (cfg->clean_headers)
    {
        /* pop the proxy's IP from the list */
        apr_array_pop(arr);
        if (apr_is_empty_array(arr))
            apr_table_unset(r->headers_in, header_ip);
        else {
            char *ip_list = apr_array_pstrcat(r->pool, arr, ',');
            apr_table_set(r->headers_in, header_ip, ip_list);
        }
    }

    // store information later used in cleaning up after ourselves
    // cleanup is important especially for the connection information
    // as that might be reused in pipelining connections but the X-Forwarded
    // situation might be totally unrelated in later requests using the same
    // connection
    rpaf_cleanup_rec *rcr = (rpaf_cleanup_rec *)apr_pcalloc(r->pool, sizeof(rpaf_cleanup_rec));
    rcr->old_useragent_ip = apr_pstrdup(r->pool, r->useragent_ip);
    rcr->r = r;
    apr_pool_cleanup_register(r->pool, (void *)rcr, rpaf_cleanup, apr_pool_cleanup_null);
    r->useragent_ip = apr_pstrdup(r->pool, last_val);

    memcpy(&rcr->old_useragent_addr, r->useragent_addr, sizeof(apr_sockaddr_t));

    tmppool = r->useragent_addr->pool;
    tmpport = r->useragent_addr->port;
    apr_sockaddr_t *tmpsa;
    int ret = apr_sockaddr_info_get(&tmpsa, r->useragent_ip, APR_UNSPEC, tmpport, 0, tmppool);
    if (ret == APR_SUCCESS) {
      memcpy(r->useragent_addr, tmpsa, sizeof(apr_sockaddr_t));
    }
    if (cfg->sethostname) {
        const char *hostvalue;
        header_host = "X-Forwarded-Host";
        hostvalue   = apr_table_get(r->headers_in, header_host);
        if (!hostvalue) {
            header_host = "X-Host";
            hostvalue   = apr_table_get(r->headers_in, header_host);
        }

        if (!hostvalue) {
            header_host = NULL;
        } else {
            apr_array_header_t *arr = apr_array_make(r->pool, 0, sizeof(char*));
            while (*hostvalue && (val = ap_get_token(r->pool, &hostvalue, 1))) {
                *(char **)apr_array_push(arr) = apr_pstrdup(r->pool, val);
                if (*hostvalue != '\0')
                  ++hostvalue;
            }

            apr_table_set(r->headers_in, "Host", apr_pstrdup(r->pool, ((char **)arr->elts)[((arr->nelts)-1)]));
            r->hostname = apr_pstrdup(r->pool, ((char **)arr->elts)[((arr->nelts)-1)]);
// r->useragent_host was introduced in 2.4.19 (see comment at start of file)
#if AP_SERVER_MINORVERSION_NUMBER > 3 && AP_SERVER_PATCHLEVEL_NUMBER > 18
            r->useragent_host = apr_pstrdup(r->pool, ((char **)arr->elts)[((arr->nelts)-1)]);
#endif
            ap_update_vhost_from_headers(r);
        }
    }

    if (cfg->sethttps) {
        const char *httpsvalue, *scheme;
        header_https = "X-Forwarded-HTTPS";
        httpsvalue   = apr_table_get(r->headers_in, header_https);
        if (!httpsvalue) {
            header_https = "X-HTTPS";
            httpsvalue   = apr_table_get(r->headers_in, header_https);
        }

        if (!httpsvalue) {
            header_https = "X-Forwarded-Proto";
            httpsvalue   = apr_table_get(r->headers_in, header_https);
            if (!httpsvalue) {
              header_https = "X-Forwarded-Protocol";
              httpsvalue   = apr_table_get(r->headers_in, header_https);
            }
            if (httpsvalue) {
                if (strcmp(httpsvalue, cfg->https_scheme) == 0) {
                    apr_table_set(r->connection->notes, "rpaf_https", "on");
                    apr_table_set(r->subprocess_env   , "HTTPS"     , "on");
                    r->parsed_uri.scheme = apr_pstrdup(r->pool, cfg->https_scheme);
                }
            } else {
                header_https = NULL;
            }
        } else {
            if(strcmp(httpsvalue, "on") == 0 || strcmp(httpsvalue, "On") == 0) {
              apr_table_set(r->connection->notes, "rpaf_https", "on");
              apr_table_set(r->subprocess_env   , "HTTPS"     , "on");
              r->parsed_uri.scheme = apr_pstrdup(r->pool, cfg->https_scheme);
            }
        }

    }

     if (cfg->setport) {
        const char *portvalue;
        header_port = "X-Forwarded-Port";
        portvalue   = apr_table_get(r->headers_in, header_port);
        if (!portvalue) {
            header_port = "X-Port";
            portvalue   = apr_table_get(r->headers_in, header_port);
        }

        if (!portvalue) {
            header_port            = NULL;
            r->parsed_uri.port     = 0;
            r->parsed_uri.port_str = NULL;
        } else {
            r->parsed_uri.port     = atoi(portvalue);
            r->parsed_uri.port_str = apr_pstrdup(r->pool, portvalue);
        }
    }

    if (cfg->clean_headers) {
        if (header_host ) apr_table_unset(r->headers_in, header_host );
        if (header_https) apr_table_unset(r->headers_in, header_https);
        if (header_port ) apr_table_unset(r->headers_in, header_port );
    }

    return DECLINED;
}

static const command_rec rpaf_cmds[] = {
    AP_INIT_FLAG(
                 "RPAF_Enable",
                 rpaf_enable,
                 NULL,
                 RSRC_CONF,
                 "Enable mod_rpaf"
                 ),
    AP_INIT_FLAG(
                 "RPAF_SetHostName",
                 rpaf_sethostname,
                 NULL,
                 RSRC_CONF,
                 "Let mod_rpaf set the hostname from the X-Host header and update vhosts"
                 ),
    AP_INIT_FLAG(
                 "RPAF_SetHTTPS",
                 rpaf_sethttps,
                 NULL,
                 RSRC_CONF,
                 "Let mod_rpaf set the HTTPS environment variable from the X-HTTPS header"
                 ),
    AP_INIT_FLAG(
                 "RPAF_SetPort",
                 rpaf_setport,
                 NULL,
                 RSRC_CONF,
                 "Let mod_rpaf set the server port from the X-Port header"
                 ),
    AP_INIT_FLAG(
                 "RPAF_ForbidIfNotProxy",
                 rpaf_set_forbid_if_not_proxy,
                 NULL,
                 RSRC_CONF,
                 "Deny access if connection not from trusted RPAF_ProxyIPs"
                 ),
    AP_INIT_FLAG(
                 "RPAF_CleanHeaders",
                 rpaf_set_clean_headers,
                 NULL,
                 RSRC_CONF,
                 "Remove forwarded headers from the request"
                 ),
    AP_INIT_ITERATE(
                 "RPAF_ProxyIPs",
                 rpaf_set_proxy_ip,
                 NULL,
                 RSRC_CONF,
                 "IP(s) of Proxy server setting X-Forwarded-For header"
                 ),
    AP_INIT_TAKE1(
                 "RPAF_Header",
                 rpaf_set_headername,
                 NULL,
                 RSRC_CONF,
                 "Which header to look for when trying to find the real ip of the client in a proxy setup"
                 ),
    { NULL }
};

static int ssl_is_https(conn_rec *c) {
    return apr_table_get(c->notes, "rpaf_https") != NULL;
}

static void rpaf_register_hooks(apr_pool_t *p) {
    ap_hook_post_read_request(rpaf_post_read_request, NULL, NULL, APR_HOOK_FIRST);

    /* this will only work if mod_ssl is not loaded */
    if (APR_RETRIEVE_OPTIONAL_FN(ssl_is_https) == NULL)
        APR_REGISTER_OPTIONAL_FN(ssl_is_https);
}

module AP_MODULE_DECLARE_DATA rpaf_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    rpaf_create_server_cfg,
    NULL,
    rpaf_cmds,
    rpaf_register_hooks,
};

/*
   Author : xiaoff
   E-mail : zhaofeng_0019@163.com

   This is a nginx module that can resolve domain names inside upstreams and
   keep them up to date.

   Basically it's using
   https://github.com/GUI/nginx-upstream-dynamic-servers and fix almost all the
   possible problem
   (https://github.com/GUI/nginx-upstream-dynamic-servers/issues).

   Not like a typical nginx third part module, to using this module, you may
   have to do some modification in native nginx code, trust me, it's harmless
   and just a little. You can see it in README.md.

   you can also use the origin way that https://github.com/GUI/nginx-upstream-dynamic-servers used, which is overwriting the native server directive,by doing a little modification in my code (by compare the ngx_http_upstream_dynamic_resolve_directive in my code and ngx_http_upstream_dynamic_server_directive in previous project), but i think it's not convenient when original code changes.

   you can also see my pull request to the previous project https://github.com/GUI/nginx-upstream-dynamic-servers/pull/33  
   but it only solve the memory problem.

   Thanks for Nick Muerdter, Wandenberg Peixoto, Edward Riede
   Under MIT License

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
   LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
   OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
   WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

*/
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
    ngx_resolver_t *resolver;
    ngx_msec_t resolver_timeout;
    ngx_array_t dynamic_servers;
    ngx_http_conf_ctx_t *conf_ctx;
} ngx_http_upstream_dynamic_resolve_server_main_conf_t;

typedef struct
{
    ngx_queue_t queue;
    ngx_pool_t *pool;
    ngx_uint_t refer_num;
} ngx_http_upstream_dynamic_resolve_server_pool_node_t;

typedef struct
{
    ngx_http_upstream_dynamic_resolve_server_pool_node_t *cur_node;
    ngx_queue_t pool_queue;
    ngx_uint_t pool_queue_len;
    ngx_int_t resolve_num;
    ngx_http_upstream_server_t *server;
    ngx_http_upstream_srv_conf_t *upstream_conf;
    ngx_str_t origin_url;
    ngx_str_t host;
    in_port_t port;
    ngx_event_t timer;
    ngx_int_t use_last;
    ngx_http_upstream_init_peer_pt original_init_peer;
} ngx_http_upstream_dynamic_resolve_server_conf_t;

typedef struct
{
    ngx_http_upstream_dynamic_resolve_server_conf_t *dynamic_server;
    void *data;
    ngx_event_get_peer_pt original_get_peer;
    ngx_event_free_peer_pt original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt original_set_session;
    ngx_event_save_peer_session_pt original_save_session;
#endif
    ngx_http_upstream_dynamic_resolve_server_pool_node_t *pool_node;
} ngx_http_upstream_dynamic_resolve_peer_data_t;

static ngx_str_t ngx_http_upstream_dynamic_resolve_server_null_route =
    ngx_string("127.255.255.255");

static void *ngx_http_upstream_dynamic_resolve_server_main_conf(ngx_conf_t *cf);

ngx_int_t ngx_http_upstream_dynamic_resolve_directive(
    ngx_conf_t *cf, ngx_http_upstream_server_t *us, ngx_uint_t *i);
static char *
ngx_http_upstream_dynamic_resolve_servers_merge_conf(ngx_conf_t *cf,
                                                     void *parent, void *child);
static ngx_int_t
ngx_http_upstream_dynamic_resolve_servers_init_process(ngx_cycle_t *cycle);

static void ngx_http_upstream_dynamic_resolve_server(ngx_event_t *ev);

static void
ngx_http_upstream_dynamic_resolve_server_handler(ngx_resolver_ctx_t *ctx);

static ngx_http_upstream_dynamic_resolve_server_conf_t *find_dynamic_server(ngx_http_upstream_srv_conf_t *us);
static ngx_int_t
ngx_http_upstream_init_dynamic_resolve_server_peer(ngx_http_request_t *r,
                                                   ngx_http_upstream_srv_conf_t *us);

static ngx_int_t ngx_http_upstream_get_dynamic_resolve_server_peer(ngx_peer_connection_t *pc,
                                                                   void *data);

static void ngx_http_upstream_free_dynamic_resolve_peer(ngx_peer_connection_t *pc,
                                                        void *data, ngx_uint_t state);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_dynamic_resolve_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_dynamic_resolve_save_session(ngx_peer_connection_t *pc,
                                                           void *data);
#endif

static void ngx_http_upstream_dynamic_resolve_servers_clean_up(void *data);

static ngx_http_module_t ngx_http_upstream_dynamic_resolve_servers_module_ctx =
    {
        NULL, /* preconfiguration */
        NULL, /* postconfiguration */

        ngx_http_upstream_dynamic_resolve_server_main_conf, /* create main
                                                               configuration */
        NULL,                                               /* init main configuration */

        NULL,                                                 /* create server configuration */
        ngx_http_upstream_dynamic_resolve_servers_merge_conf, /* merge server
                                                                 configuration
                                                               */

        NULL, /* create location configuration */
        NULL  /* merge location configuration */
};

ngx_module_t ngx_http_upstream_dynamic_resolve_servers_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_dynamic_resolve_servers_module_ctx,  /* module context */
    NULL,                                                   /* module directives */
    NGX_HTTP_MODULE,                                        /* module type */
    NULL,                                                   /* init master */
    NULL,                                                   /* init module */
    ngx_http_upstream_dynamic_resolve_servers_init_process, /* init process */
    NULL,                                                   /* init thread */
    NULL,                                                   /* exit thread */
    NULL,                                                   /* exit process */
    NULL,                                                   /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_upstream_dynamic_resolve_server_conf_t *find_dynamic_server(ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_dynamic_resolve_server_main_conf_t *udrsmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_dynamic_resolve_servers_module);
    ngx_http_upstream_dynamic_resolve_server_conf_t *dynamic_server = udrsmcf->dynamic_servers.elts;
    ngx_uint_t i;

    for (i = 0; i < udrsmcf->dynamic_servers.nelts; i++)
    {
        if (dynamic_server[i].upstream_conf == us)
        {
            return &dynamic_server[i];
        }
    }
    return NULL;
}

static void ngx_http_upstream_dynamic_resolve_servers_clean_up(void *data)
{
    ngx_http_upstream_dynamic_resolve_server_pool_node_t *node = data;
    node->refer_num--;
}

static ngx_int_t
ngx_http_upstream_init_dynamic_resolve_server_peer(ngx_http_request_t *r,
                                                   ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_dynamic_resolve_server_conf_t *dynamic_server = find_dynamic_server(us);
    ngx_pool_cleanup_t *cleanup = ngx_pool_cleanup_add(r->pool, 0);
    ngx_http_upstream_dynamic_resolve_peer_data_t *drp;
    cleanup->data = dynamic_server->cur_node;
    cleanup->handler = ngx_http_upstream_dynamic_resolve_servers_clean_up;
    dynamic_server->cur_node->refer_num++;
    if (dynamic_server->original_init_peer(r, us) != NGX_OK)
    {
        return NGX_ERROR;
    }
    *drp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_dynamic_resolve_peer_data_t));
    if (drp == NULL)
    {
        return NGX_ERROR;
    }
    drp->data = r->upstream->peer.data;
    drp->original_get_peer = r->upstream->peer.get;
    r->upstream->peer.get = ngx_http_upstream_get_dynamic_resolve_server_peer;
    drp->original_free_peer = r->upstream->peer.free;
    r->upstream->peer.free = ngx_http_upstream_free_dynamic_resolve_peer;
    drp->dynamic_server = dynamic_server;
    drp->pool_node = dynamic_server->cur_node;
#if (NGX_HTTP_SSL)
    drp->original_set_session = r->upstream->peer.set_session;
    drp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_dynamic_resolve_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_dynamic_resolve_save_session;
#endif
    r->upstream->peer.data = drp;
    return NGX_OK;
}

static ngx_int_t ngx_http_upstream_get_dynamic_resolve_server_peer(ngx_peer_connection_t *pc,
                                                                   void *data)
{
    ngx_http_upstream_dynamic_resolve_peer_data_t *drp = data;
    if (drp->dynamic_server->cur_node != drp->pool_node)
    {
        /* if get peer after dns updated the old backend maybe unusable, so return error in get_peer function to prevent send upstream request to the wrong backend */
        return NGX_ERROR;
    }
    return drp->original_get_peer(pc, drp->data);
}

static void ngx_http_upstream_free_dynamic_resolve_peer(ngx_peer_connection_t *pc,
                                                        void *data, ngx_uint_t state)
{
    ngx_http_upstream_dynamic_resolve_peer_data_t *drp = data;
    drp->original_free_peer(pc, drp->data, state);
}

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_dynamic_resolve_set_session(
    ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_dynamic_resolve_peer_data_t *drp = data;
    return drp->original_set_session(pc, drp->data);
}
static void ngx_http_upstream_dynamic_resolve_save_session(ngx_peer_connection_t *pc,
                                                           void *data)
{
    ngx_http_upstream_dynamic_resolve_peer_data_t *drp = data;
    return drp->original_save_session(pc, drp->data);
}
#endif
ngx_int_t ngx_http_upstream_dynamic_resolve_directive(
    ngx_conf_t *cf, ngx_http_upstream_server_t *us, ngx_uint_t *i)
{
    ngx_http_upstream_srv_conf_t *uscf =
        ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    ngx_http_upstream_dynamic_resolve_server_main_conf_t *udrsmcf =
        ngx_http_conf_get_module_main_conf(
            cf, ngx_http_upstream_dynamic_resolve_servers_module);
    ngx_http_upstream_dynamic_resolve_server_conf_t *dynamic_server = NULL;
    ngx_url_t u;
    ngx_str_t *value = cf->args->elts;

    if (ngx_strncmp(value[(*i)].data, "resolve", 7) != 0)
    {
        return NGX_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];

    /* replace value[1] to static to prevent nginx take too long time to resolve
     * it using function ngx_parse_url in function ngx_http_upstream_server it
     * doesn't matter if a server will be dynamic resolved
     */

    value[1] = ngx_http_upstream_dynamic_resolve_server_null_route;
    u.default_port = 80;
    u.no_resolve = 1;
    ngx_parse_url(cf->pool, &u);
    if (!u.addrs || !u.addrs[0].sockaddr)
    {
        dynamic_server = ngx_array_push(&udrsmcf->dynamic_servers);
        if (dynamic_server == NULL)
        {
            return NGX_ERROR;
        }
        ngx_memzero(dynamic_server,
                    sizeof(ngx_http_upstream_dynamic_resolve_server_conf_t));
        us->down = 1;
        dynamic_server->server = us;
        dynamic_server->upstream_conf = uscf;
        dynamic_server->host = u.host;
        dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
        dynamic_server->origin_url = u.url;
        ngx_queue_init(&dynamic_server->pool_queue);
    }

    if (*i == cf->args->nelts - 1 ||
        ngx_strncmp(value[(*i) + 1].data, "use_last", 8) != 0)
    {
        return NGX_AGAIN;
    }

    (*i)++;
    dynamic_server->use_last = 1;
    return NGX_AGAIN;
}

static void *
ngx_http_upstream_dynamic_resolve_server_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_dynamic_resolve_server_main_conf_t *udrsmcf;

    udrsmcf = ngx_pcalloc(
        cf->pool, sizeof(ngx_http_upstream_dynamic_resolve_server_main_conf_t));
    if (udrsmcf == NULL)
    {
        return NULL;
    }

    if (ngx_array_init(
            &udrsmcf->dynamic_servers, cf->pool, 1,
            sizeof(ngx_http_upstream_dynamic_resolve_server_conf_t)) !=
        NGX_OK)
    {
        return NULL;
    }

    udrsmcf->resolver_timeout = NGX_CONF_UNSET_MSEC;

    return udrsmcf;
}

static char *ngx_http_upstream_dynamic_resolve_servers_merge_conf(
    ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upstream_dynamic_resolve_server_main_conf_t *udrsmcf =
        ngx_http_conf_get_module_main_conf(
            cf, ngx_http_upstream_dynamic_resolve_servers_module);

    if (udrsmcf->dynamic_servers.nelts > 0)
    {
        ngx_http_core_loc_conf_t *core_loc_conf =
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
#if nginx_version >= 1009011
        if (core_loc_conf->resolver == NULL ||
            core_loc_conf->resolver->connections.nelts == 0)
        {
#else
        if (core_loc_conf->resolver == NULL ||
            core_loc_conf->resolver->udp_connections.nelts == 0)
        {
#endif
            ngx_conf_log_error(
                NGX_LOG_ERR, cf, 0,
                "resolver must be defined at the 'http' level of the config");
            return NGX_CONF_ERROR;
        }
        udrsmcf->conf_ctx = cf->ctx;
        udrsmcf->resolver = core_loc_conf->resolver;
        ngx_conf_merge_msec_value(udrsmcf->resolver_timeout,
                                  core_loc_conf->resolver_timeout, 30000);
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_upstream_dynamic_resolve_servers_init_process(ngx_cycle_t *cycle)
{
    ngx_http_upstream_dynamic_resolve_server_main_conf_t *udrsmcf =
        ngx_http_cycle_get_module_main_conf(
            cycle, ngx_http_upstream_dynamic_resolve_servers_module);
    ngx_http_upstream_dynamic_resolve_server_conf_t *dynamic_server =
        udrsmcf->dynamic_servers.elts;
    ngx_uint_t i;
    ngx_event_t *timer;
    for (i = 0; i < udrsmcf->dynamic_servers.nelts; i++)
    {
        timer = &dynamic_server[i].timer;
        timer->handler = ngx_http_upstream_dynamic_resolve_server;
        timer->log = cycle->log;
        timer->data = &dynamic_server[i];
        dynamic_server[i].server->name = dynamic_server->origin_url;
        dynamic_server[i].original_init_peer = dynamic_server[i].upstream_conf->peer.init;
        ngx_http_upstream_dynamic_resolve_server(timer);
    }

    return NGX_OK;
}

static void ngx_http_upstream_dynamic_resolve_server(ngx_event_t *ev)
{
    ngx_http_upstream_dynamic_resolve_server_main_conf_t *udrsmcf =
        ngx_http_cycle_get_module_main_conf(
            ngx_cycle, ngx_http_upstream_dynamic_resolve_servers_module);
    ngx_http_upstream_dynamic_resolve_server_conf_t *dynamic_server;
    ngx_resolver_ctx_t *ctx;
    ngx_uint_t refresh_in = 1000;
    dynamic_server = ev->data;

    ctx = ngx_resolve_start(udrsmcf->resolver, NULL);
    if (ctx == NULL)
    {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: resolver start error for '%V'",
                      &dynamic_server->host);
        return;
    }

    if (ctx == NGX_NO_RESOLVER)
    {
        ngx_log_error(
            NGX_LOG_ALERT, ev->log, 0,
            "upstream-dynamic-servers: no resolver defined to resolve '%V'",
            &dynamic_server->host);
        return;
    }

    ctx->name = dynamic_server->host;
    ctx->handler = ngx_http_upstream_dynamic_resolve_server_handler;
    ctx->data = dynamic_server;
    ctx->timeout = udrsmcf->resolver_timeout;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ev->log, 0,
                  "upstream-dynamic-servers: Resolving '%V'", &ctx->name);
    if (ngx_resolve_name(ctx) != NGX_OK)
    {
        ngx_log_error(
            NGX_LOG_ALERT, ev->log, 0,
            "upstream-dynamic-servers: ngx_resolve_name failed for '%V'",
            &ctx->name);
        if (dynamic_server->resolve_num == 0)
        {
            dynamic_server->resolve_num = 1;
            refresh_in = ngx_random() % 5000;
        }
        ngx_add_timer(&dynamic_server->timer, refresh_in);
    }
}

static void
ngx_http_upstream_dynamic_resolve_server_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_http_upstream_dynamic_resolve_server_main_conf_t *udrsmcf =
        ngx_http_cycle_get_module_main_conf(
            ngx_cycle, ngx_http_upstream_dynamic_resolve_servers_module);
    ngx_http_upstream_dynamic_resolve_server_conf_t *dynamic_server;
    ngx_conf_t cf;
    ngx_addr_t *addrs;
    ngx_pool_t *new_pool;
    ngx_http_upstream_dynamic_resolve_server_pool_node_t *pool_node, *tmp_node;
    ngx_queue_t *p, *n, *pool_queue;
    ngx_uint_t index = 0;
    ngx_uint_t refresh_in = 1000;
    dynamic_server = ctx->data;
    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                  "upstream-dynamic-servers: Finished resolving '%V'",
                  &ctx->name);

    if (dynamic_server->use_last && ctx->state == NGX_RESOLVE_TIMEDOUT)
    {
        ngx_log_error(
            NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: '%V' resolve timeout and use last ip",
            &ctx->name);
        goto end;
    }

    if (ctx->state)
    {
        ngx_log_error(
            NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: '%V' could not be resolved (%i: %s)",
            &ctx->name, ctx->state, ngx_resolver_strerror(ctx->state));

        ngx_url_t u;
        ngx_memzero(&u, sizeof(ngx_url_t));

        // If the domain fails to resolve on start up, assign a static IP that
        // should never route (we'll also mark it as down in the upstream later
        // on). This is to account for various things inside nginx that seem to
        // expect a server to always have at least 1 IP.

        u.url = ngx_http_upstream_dynamic_resolve_server_null_route;
        u.default_port = 80;
        u.no_resolve = 1;
        if (ngx_parse_url(ngx_cycle->pool, &u) != NGX_OK)
        {
            if (u.err)
            {
                ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                              "%s in upstream \"%V\"", u.err, &u.url);
            }

            goto end;
        }
        ctx->addr.sockaddr = u.addrs[0].sockaddr;
        ctx->addr.socklen = u.addrs[0].socklen;
        ctx->addr.name = u.addrs[0].name;
        ctx->addrs = &ctx->addr;
        ctx->naddrs = u.naddrs;
    }

    if (ctx->naddrs != dynamic_server->server->naddrs)
    {
        goto reinit_upstream;
    }

    ngx_uint_t i, j, founded;
    ngx_addr_t *existing_addr;
    for (i = 0; i < ctx->naddrs; i++)
    {
        founded = 0;

        for (j = 0; j < ctx->naddrs; j++)
        {
            existing_addr = &dynamic_server->server->addrs[j];
            if (ngx_cmp_sockaddr(existing_addr->sockaddr,
                                 existing_addr->socklen, ctx->addrs[i].sockaddr,
                                 ctx->addrs[i].socklen, 0) == NGX_OK)
            {
                founded = 1;
                break;
            }
        }

        if (!founded)
        {
            goto reinit_upstream;
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                  "upstream-dynamic-servers: No DNS changes for '%V' - keeping "
                  "existing upstream configuration",
                  &ctx->name);
    goto end;

reinit_upstream:

    new_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ctx->resolver->log);
    if (new_pool == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                      "upstream-dynamic-servers: Could not create new pool");
        goto end;
    }

    pool_node = ngx_palloc(
        new_pool, sizeof(ngx_http_upstream_dynamic_resolve_server_pool_node_t));
    if (pool_node == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                      "upstream-dynamic-servers: Could not create pool_node");
        goto end;
    }
    pool_node->pool = new_pool;
    pool_node->refer_num = 0;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                  "upstream-dynamic-servers: DNS changes for '%V' detected - "
                  "reinitialize upstream configuration",
                  &ctx->name);

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.name = "dynamic_server_init_upstream";
    cf.cycle = (ngx_cycle_t *)ngx_cycle;
    cf.pool = new_pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.log = ngx_cycle->log;
    cf.ctx = udrsmcf->conf_ctx;

    addrs = ngx_pcalloc(new_pool, ctx->naddrs * sizeof(ngx_addr_t));
    ngx_memcpy(addrs, ctx->addrs, ctx->naddrs * sizeof(ngx_addr_t));

    struct sockaddr *sockaddr;
    ngx_addr_t *addr;
    socklen_t socklen;
    for (i = 0; i < ctx->naddrs; i++)
    {
        addr = &addrs[i];

        socklen = ctx->addrs[i].socklen;

        sockaddr = ngx_palloc(new_pool, socklen);
        ngx_memcpy(sockaddr, ctx->addrs[i].sockaddr, socklen);
        switch (sockaddr->sa_family)
        {
        case AF_INET6:
            ((struct sockaddr_in6 *)sockaddr)->sin6_port =
                htons((u_short)dynamic_server->port);
            break;
        default:
            ((struct sockaddr_in *)sockaddr)->sin_port =
                htons((u_short)dynamic_server->port);
        }

        addr->sockaddr = sockaddr;
        addr->socklen = socklen;

        u_char *p;
        size_t len;

        p = ngx_pnalloc(new_pool, NGX_SOCKADDR_STRLEN);
        if (p == NULL)
        {
            ngx_log_error(
                NGX_LOG_ERR, ctx->resolver->log, 0,
                "upstream-dynamic-servers: Error initializing sockaddr");
            ngx_destroy_pool(new_pool);
            goto end;
        }
        len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);
        addr->name.len = len;
        addr->name.data = p;
        ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                      "upstream-dynamic-servers: '%V' was resolved to '%V'",
                      &ctx->name, &addr->name);
    }

    // If the domain failed to resolve, mark this server as down.
    dynamic_server->server->down = ctx->state ? 1 : 0;
    dynamic_server->server->addrs = addrs;
    dynamic_server->server->naddrs = ctx->naddrs;

    if (ngx_http_upstream_init_round_robin(
            &cf, dynamic_server->upstream_conf) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                      "upstream-dynamic-servers: Error re-initializing "
                      "upstream after DNS changes");
    }

    dynamic_server->upstream_conf->peer.init = ngx_http_upstream_init_dynamic_resolve_server_peer;

    pool_queue = &dynamic_server->pool_queue;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                  "upstream-dynamic-servers: server '%V' pool_queue_len is %i "
                  "before insert",
                  &dynamic_server->host, dynamic_server->pool_queue_len);

    for (p = pool_queue->next, n = p->next; p != pool_queue;
         p = n, n = n->next)
    {
        index++;
        tmp_node = ngx_queue_data(
            p, ngx_http_upstream_dynamic_resolve_server_pool_node_t, queue);
        if (tmp_node->refer_num == 0)
        {
            ngx_queue_remove(p);

            ngx_log_debug(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                          "upstream-dynamic-servers: server '%V' %ith pool "
                          "will be destoried",
                          &dynamic_server->host, index);

            ngx_destroy_pool(tmp_node->pool);
            dynamic_server->pool_queue_len--;
        }
    }

    ngx_queue_insert_tail(pool_queue, &pool_node->queue);
    dynamic_server->cur_node = pool_node;
    dynamic_server->pool_queue_len++;

end:

    ngx_resolve_name_done(ctx);

    if (ngx_exiting)
    {
        ngx_log_debug(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                      "upstream-dynamic-servers: worker is about to exit, do "
                      "not set the timer again");
        return;
    }
    if (dynamic_server->resolve_num == 0)
    {
        dynamic_server->resolve_num = 1;
        refresh_in = ngx_random() % 5000;
    }
    ngx_add_timer(&dynamic_server->timer, refresh_in);
}

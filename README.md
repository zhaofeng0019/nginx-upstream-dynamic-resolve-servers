# nginx-upstream-dynamic-resolve-servers

[English](./README.md)  |  [中文](./README.cn.md)  
An nginx module to resolve domain names inside upstreams and keep them up to date.

By default, servers defined in nginx upstreams are only resolved when nginx starts. This module provides an additional `resolve` parameter for `server` definitions that can be used to asynchronously resolve upstream domain names. This keeps the upstream definition up to date according to the DNS TTL of each domain names. This can be useful if you want to use upstreams for dynamic types of domain names that may frequently change IP addresses. And there is another additional `use_last` parameter that can be used to make nginx to use the last result when DNS resolve timeout.

This module also allows nginx to start if an upstream contains a defunct domain name that no longer resolves. By default, nginx will fail to start if an upstream server contains an unresolvable domain name. With this module, nginx is still allowed to start with invalid domain names, but an error will be logged and the unresolvable domain names will be marked as down. if you add resolve parameter behind a server, it will be replaced to a useless ip at beginning. So it will not take a long time to wait for the result of ngx_parse_url in native process. Don't worry about this, it will be replaced back and to dynamic DNS resolve in the init_process.

Notice: 

1. Unlike other nginx modules, before you using this module, you should do some modification in the native nginx code. You can also use the origin way that https://github.com/GUI/nginx-upstream-dynamic-servers used, which is overwriting the native server directive that no need modification in the native code, by doing a little modification in my code (by compare the ngx_http_upstream_dynamic_resolve_directive in my code and ngx_http_upstream_dynamic_server_directive in previous project), but I think it's not convenient when original code changes. I change the names of the functions and structs in the previous project just for my owner taste.You can also see my pull request to the previous project https://github.com/GUI/nginx-upstream-dynamic-servers/pull/33  
  but it only solve the memory problem.

2. This module works well with the native nginx upstream module. If you are using other nginx third party upstream modules, you may should read the code and think about it.

## Installation

### modification

ngx_http_upstream.c 

```c
extern ngx_int_t ngx_http_upstream_dynamic_resolve_directive(ngx_conf_t *cf,         /* add */
ngx_http_upstream_server_t *us, ngx_uint_t *i);                                      /* add */

static char *
ngx_http_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
      ...
      for (i = 2; i < cf->args->nelts; i++) {

        ngx_int_t res = ngx_http_upstream_dynamic_resolve_directive(cf, us, &i);  /* add */
        if (res == NGX_ERROR) {                                                   /* add */
            goto invalid;                                                         /* add */
        } else if (res == NGX_AGAIN) {                                            /* add */
            continue;                                                             /* add */
        }                                                                         /* add */
      ...
      }
      ...
}
```

### configure and make
```sh
./configure --add-module=/path/to/nginx-upstream-dynamic-resolve-servers
make && make install
```


## Usage

Use the `server` definition inside your upstreams and specify the `resolve` parameter.

*Note:* 

1. A `resolver` must be defined at the `http` level of nginx's config for `resolve` to work.  
2. The `use_last` parameter must behind `resolve` parameter.  
3. For one domain, if you don't add `resolve` parameter in the `server` directive, the domain will just do nginx native process -- resolve just once and nginx will not start if the domain can't be resolved.

```
http {
  resolver 8.8.8.8;

  upstream example {
    server example.com resolve [use_last] ...;
  }
}
```

# Compatibility

Tested with nginx 1.6, 1.7, 1.8, 1.9.

## Alternatives

- [proxy_pass + resolver](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass): If you only need to proxy to 1 domain and don't need the additional capabilities of upstreams, nginx's `proxy_pass` can perform resolving at run-time.
- [ngx_upstream_jdomain](http://wiki.nginx.org/HttpUpstreamJdomainModule): An nginx module that asyncronously resolves domain names. The primary differences between jdomain and this module is that this module keeps domain names up to date even if no server traffic is being generated (jdomain requires traffic to each upstream in order to keep it up to date). This module also allows nginx to startup if unresolvable domain names are given.
- [tengine's dynamic_resolve](https://github.com/alibaba/tengine/blob/master/docs/modules/ngx_http_upstream_dynamic.md): If you're using tengine (an nginx fork), there's a new feature (currently unreleased) to support resolving domain names in upstreams at run-time.
- [NGINX Plus](http://nginx.com/resources/admin-guide/load-balancer/#resolve)

## License

nginx-upstream-resolve-dynamic-servers is open sourced under the MIT license.

## Last But Not Least

Basically, this module is using https://github.com/GUI/nginx-upstream-dynamic-servers and fix almost all the possible problem (https://github.com/GUI/nginx-upstream-dynamic-servers/issues).

Not like a typical nginx third part module, to using this module, you may have to do some modification in native nginx code, trust me, it's harmless
and just a little.

Thanks for Nick Muerdter, Wandenberg Peixoto,Edward Riede.

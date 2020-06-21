# nginx-upstream-dynamic-resolve-servers

[English](./README.md)  |  [中文](./README.cn.md)  

一个可以在upstream块里动态解析域名的nginx模块

默认情况下，nginx只会在启动的时候解析一次upstrem块里配置的域名。这个模块为`server`指令提供了`resolve`参数，可以异步解析upstream域名。如果你的upstream服务器的ip经常变动的化这个功能是非常有用的。另外，还提供了另外一个参数`use_last`，使用这个参数可以让nginx在dns解析超时的时候使用上一次的结果。

如果你的域名不能正确解析，通常情况下nginx不会正常启动，使用了这个模块之后(`server`指令后面加`resolve`,如果不加这个域名还是走原生的流程，不会动态解析)，我会在配置阶段把它替换成一个无用的ip，所以无需阻塞等待`ngx_parse_url`函数的返回值，无需担心，我会在进程的启动阶段把域名换回来并且进行动态解析。


注意: 

1. 和其它nginx第三方模块不同，在使用这个模块之前你需要对nginx原生代码进行一些修改。当然你也可以使用 https://github.com/GUI/nginx-upstream-dynamic-servers 里面的方式，也就是覆盖了原生的server指令，那样就不需要对原生的代码进行修改，只需要对我的代码做一点小改动就可以了(对比一下我代码里面的ngx_http_upstream_dynamic_resolve_directive函数和前面工程里的ngx_http_upstream_dynamic_server_directive函数)，但我觉得这样不是很好，如果原生代码的server指令发生了更改，比如增加了一些新的特性，你还要同步到自己的第三方模块里面。我改了函数名称和结构体名称只是符合我自己的命名品味。你也可以看我在前面工程里的PR https://github.com/GUI/nginx-upstream-dynamic-servers/pull/33
  不过只解决了内存的问题  

2. 如果你在`server`指令中使用了太多的参数，你可能需要修改 `NGX_CONF_MAX_ARGS`  

3. 这个模块在原生的upstream模块中可以正常使用，如果你使用了其它的第三方模块，你可能需要读一下源码并且考虑一下可行性  


## 安装 

### 修改 

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

### 编译

```sh
./configure --add-module=/path/to/nginx-upstream-dynamic-resolve-servers
make && make install
```


## 使用

在upstream里面的`server`指令的后面加上`resolve`参数，`use_last`参数为可选  

*注意：* 

1. `http`块中必须定义`resolver`  
   
2. `use_last`参数必须在`resolve`参数后面  
   
3. 如果一个域名的`server`配置项后面不加`resolve`参数，那么它会走原生的流程也就是只解析一次并且如果这个域名不能正确解析，nginx不会启动  

```
http {
  resolver 8.8.8.8;

  upstream example {
    server example.com resolve [use_last] ...;
  }
}
```

# 兼容性 

nginx 1.6, 1.7, 1.8, 1.9.

## 其它选择 

- [proxy_pass + resolver](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass): 如果你只需要动态解析一个域名并且不需要upstream块里的其它特性  
- [ngx_upstream_jdomain](http://wiki.nginx.org/HttpUpstreamJdomainModule): 和这个模块功能类似不过不能使用upstream块中的其它特性  
- [tengine's dynamic_resolve](https://github.com/alibaba/tengine/blob/master/docs/modules/ngx_http_upstream_dynamic.md): tengine里可以使用  
- [NGINX Plus](http://nginx.com/resources/admin-guide/load-balancer/#resolve) nginx的收费版  

## 许可协议 

nginx-upstream-dynamic-resolve-servers 开源并使用 MIT 许可协议  

## 写在最后

基本上这个模块的使用了 https://github.com/GUI/nginx-upstream-dynamic-servers 并且几乎全部解决了其可能存在的问题(https://github.com/GUI/nginx-upstream-dynamic-servers/issues)  

这个模块并不是一个典型的nginx第三方模块，在使用它之前，你需要对nginx的原生代码进行一些修改，改动不大并且是无害的  

感谢 Nick Muerdter, Wandenberg Peixoto, Edward Riede
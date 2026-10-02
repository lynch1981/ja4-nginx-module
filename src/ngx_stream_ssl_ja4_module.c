#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_ssl_ja4.h"
#include "ngx_http_ja4t.h"


#define NGX_STREAM_SSL_JA4         0
#define NGX_STREAM_SSL_JA4_STRING  1
#define NGX_STREAM_SSL_JA4ONE      2


#if (NGX_STREAM_SSL)
static ngx_int_t ngx_stream_ssl_ja4_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
#endif
static ngx_int_t ngx_stream_ssl_ja4t_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ssl_ja4_add_variables(ngx_conf_t *cf);


static ngx_stream_module_t  ngx_stream_ssl_ja4_module_ctx = {
    ngx_stream_ssl_ja4_add_variables,      /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


ngx_module_t  ngx_stream_ssl_ja4_module = {
    NGX_MODULE_V1,
    &ngx_stream_ssl_ja4_module_ctx,        /* module context */
    NULL,                                  /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_stream_variable_t  ngx_stream_ssl_ja4_vars[] = {

#if (NGX_STREAM_SSL)
    { ngx_string("stream_ssl_ja4"), NULL, ngx_stream_ssl_ja4_variable,
      NGX_STREAM_SSL_JA4, 0, 0 },

    { ngx_string("stream_ssl_ja4_string"), NULL, ngx_stream_ssl_ja4_variable,
      NGX_STREAM_SSL_JA4_STRING, 0, 0 },

    { ngx_string("stream_ssl_ja4one"), NULL, ngx_stream_ssl_ja4_variable,
      NGX_STREAM_SSL_JA4ONE, 0, 0 },
#endif

    { ngx_string("stream_ssl_ja4t"), NULL, ngx_stream_ssl_ja4t_variable,
      0, 0, 0 },

    { ngx_string("stream_ssl_ja4t_string"), NULL, ngx_stream_ssl_ja4t_variable,
      0, 0, 0 },

      ngx_stream_null_variable
};


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_ssl_ja4_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_str_t          fp;
    ngx_ssl_ja4_t      ja4;
    ngx_connection_t  *c;

    c = s->connection;

    /*
     * Not cached on a miss: a lookup before the handshake completes
     * must not hide the fingerprint from later lookups.
     */

    if (ngx_ssl_ja4(c, c->pool, &ja4) != NGX_OK) {
        v->not_found = 1;
        v->no_cacheable = 1;
        return NGX_OK;
    }

    ngx_str_null(&fp);

    switch (data) {

    case NGX_STREAM_SSL_JA4_STRING:
        ngx_ssl_ja4_fp_string(c->pool, &ja4, &fp);
        break;

    case NGX_STREAM_SSL_JA4ONE:
        ngx_ssl_ja4one_fp(c->pool, &ja4, &fp);
        break;

    default: /* NGX_STREAM_SSL_JA4 */
        ngx_ssl_ja4_fp(c->pool, &ja4, &fp);
    }

    if (fp.data == NULL) {
        return NGX_ERROR;
    }

    v->len = fp.len;
    v->data = fp.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_stream_ssl_ja4t_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
#ifdef NGX_HAVE_TCP_SAVE_SYN

    ngx_str_t  fp;
    ngx_int_t  rc;

    rc = ngx_http_ja4t(s->connection, &fp);

    if (rc != NGX_OK) {
        v->not_found = 1;
        return rc == NGX_ERROR ? NGX_ERROR : NGX_OK;
    }

    v->len = fp.len;
    v->data = fp.data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

#else

    v->not_found = 1;

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_stream_ssl_ja4_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_ssl_ja4_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

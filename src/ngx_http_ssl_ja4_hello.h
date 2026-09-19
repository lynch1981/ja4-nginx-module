#ifndef _NGX_HTTP_SSL_JA4_HELLO_H_INCLUDED_
#define _NGX_HTTP_SSL_JA4_HELLO_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

ngx_int_t ngx_ssl_parse_client_hello_extensions(ngx_connection_t *c);

#endif /* _NGX_HTTP_SSL_JA4_HELLO_H_INCLUDED_ */

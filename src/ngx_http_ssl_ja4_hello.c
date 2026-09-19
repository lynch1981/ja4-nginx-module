#include "ngx_http_ssl_ja4_hello.h"

// Parse extensions from raw ClientHello data
ngx_int_t
ngx_ssl_parse_client_hello_extensions(ngx_connection_t *c)
{
    const u_char  *p, *end, *exts, *ext_end;
    size_t         msg_len, sess_id_len, cipher_suites_len, comp_len;
    size_t         exts_len, ext_type, ext_len;
    ngx_array_t   *extensions;
    unsigned int  *ext_ptr;
    size_t         i;
    char           hex_str[6];

    if (c->ssl->raw_client_hello == NULL || c->ssl->raw_client_hello_len == 0) {
        return NGX_ERROR;
    }

    p = c->ssl->raw_client_hello;
    end = p + c->ssl->raw_client_hello_len;

    // Skip handshake type (1 byte)
    p++;

    if (end - p < 3) {
        return NGX_ERROR;
    }

    // Get message length (3 bytes)
    msg_len = (p[0] << 16) | (p[1] << 8) | p[2];
    p += 3;

    if (end - p < (ngx_int_t)msg_len) {
        return NGX_ERROR;
    }

    // Skip client version (2 bytes)
    if (end - p < 2) {
        return NGX_ERROR;
    }
    p += 2;

    // Skip random (32 bytes)
    if (end - p < 32) {
        return NGX_ERROR;
    }
    p += 32;

    // Get session ID length (1 byte)
    if (end - p < 1) {
        return NGX_ERROR;
    }
    sess_id_len = *p++;

    // Skip session ID
    if (end - p < (ssize_t)sess_id_len) {
        return NGX_ERROR;
    }
    p += sess_id_len;

    // Get cipher suites length (2 bytes)
    if (end - p < 2) {
        return NGX_ERROR;
    }
    cipher_suites_len = (p[0] << 8) | p[1];
    p += 2;

    // Parse cipher suites to detect SCSV values
    if (end - p < (ssize_t)cipher_suites_len) {
        return NGX_ERROR;
    }

    const u_char *cs_p = p;
    const u_char *cs_end = p + cipher_suites_len;

    while (cs_p + 1 < cs_end) {
        unsigned int cipher = (cs_p[0] << 8) | cs_p[1];

        // Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)
        if (cipher == 0x00ff) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                          "Detected TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)");
        }

        cs_p += 2;
    }

    p += cipher_suites_len;

    // Get compression methods length (1 byte)
    if (end - p < 1) {
        return NGX_ERROR;
    }
    comp_len = *p++;

    // Skip compression methods
    if (end - p < (ssize_t)comp_len) {
        return NGX_ERROR;
    }
    p += comp_len;

    // Check if extensions are present
    if (end - p < 2) {
        // No extensions
        return NGX_OK;
    }

    // Get extensions length (2 bytes)
    exts_len = (p[0] << 8) | p[1];
    p += 2;

    if (end - p < (ssize_t)exts_len) {
        return NGX_ERROR;
    }

    exts = p;
    ext_end = p + exts_len;

    // Create a temporary array to store all extension types
    extensions = ngx_array_create(c->pool, 32, sizeof(unsigned int));
    if (extensions == NULL) {
        return NGX_ERROR;
    }

    // Parse all extensions
    p = exts;
    while (p + 3 < ext_end) {
        ext_type = (p[0] << 8) | p[1];
        ext_len = (p[2] << 8) | p[3];
        p += 4;

        if (ext_end - p < (ngx_int_t)ext_len) {
            return NGX_ERROR;
        }

        // Add extension type to array
        ext_ptr = ngx_array_push(extensions);
        if (ext_ptr == NULL) {
            return NGX_ERROR;
        }
        *ext_ptr = ext_type;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                      "Found extension: 0x%04xi (length: %uz)", ext_type, ext_len);

        // Check for supported_versions extension (0x002b)
        if (ext_type == 0x002b && ext_len >= 3) {
            const u_char *sv = p;
            size_t list_len = sv[0];

            if (list_len + 1 <= ext_len) {
                const u_char *versions = sv + 1;
                int highest = 0;

                for (size_t j = 0; j + 1 < list_len; j += 2) {
                    int ver = (versions[j] << 8) | versions[j + 1];

                    // Skip GREASE values (RFC 8701)
                    if ((ver & 0x0f0f) == 0x0a0a) {
                        continue;
                    }

                    if (ver > highest) {
                        highest = ver;
                    }
                }

                if (highest != 0) {
                    c->ssl->highest_supported_tls_client_version = highest;
                    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                  "Highest TLS version from supported_versions: 0x%04xd",
                                  highest);
                }
            }
        }

        p += ext_len;
    }

    // Convert extensions array to hex strings
    c->ssl->extensions_sz = extensions->nelts;
    c->ssl->extensions = ngx_palloc(c->pool, sizeof(char *) * extensions->nelts);

    if (c->ssl->extensions == NULL) {
        return NGX_ERROR;
    }

    ext_ptr = extensions->elts;
    for (i = 0; i < extensions->nelts; i++) {
        snprintf(hex_str, sizeof(hex_str), "%04x", ext_ptr[i]);

        c->ssl->extensions[i] = ngx_pnalloc(c->pool, sizeof(hex_str));
        if (c->ssl->extensions[i] == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(c->ssl->extensions[i], hex_str, sizeof(hex_str));

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                      "c->ssl->extensions[%uz] = %s", i, c->ssl->extensions[i]);
    }

    return NGX_OK;
}

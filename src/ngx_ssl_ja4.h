#ifndef _NGX_SSL_JA4_H_INCLUDED_
#define _NGX_SSL_JA4_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_ssl_ja4_s
{
    char *version; // TLS version
    char *highest_supported_tls_client_version;

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    unsigned char has_sni; // 'd' if SNI is present, 'i' otherwise

    size_t ciphers_sz; // Count of ciphers
    char **ciphers;    // List of ciphers

    // size according to ja4 spec, can be 1-2 larger than extensions_sz
    size_t extensions_count; // Count of extensions including ignored extensions (ALPN, SNI)
    // actual size of extensions array
    size_t extensions_sz; // Count of extensions NOT including ignored extensions (ALPN, SNI), for mem alloc etc
    char **extensions;    // List of extensions

    // JA4one
    size_t extensions_no_psk_count; // Count of extensions including GREASE values
    char **extensions_no_psk;       // List of extensions including GREASE values

    // this hash does not include signature algorithms for the time being
    char extension_hash_no_psk[65];           // Full SHA256 hash (32 bytes * 2 characters/byte + 1 for '\0')
    char extension_hash_no_psk_truncated[13]; // Truncated SHA256 hash (12 bytes * 2 characters/byte + 1 for '\0')

    size_t sigalgs_sz; // Count of signature algorithms
    char **sigalgs;    // List of signature algorithms

    // For the first and last ALPN extension values
    char *alpn_first_value;

    char cipher_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char cipher_hash_truncated[13]; // 12 bytes * 2 characters/byte + 1 for '\0'

    char extension_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char extension_hash_truncated[13]; // 6 bytes * 2 characters/byte + 1 for '\0'

} ngx_ssl_ja4_t;


int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4);
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
void ngx_ssl_ja4_fp_string(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
void ngx_ssl_ja4one_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);


#endif /* _NGX_SSL_JA4_H_INCLUDED_ */

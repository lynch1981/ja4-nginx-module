/* JA4 TLS client fingerprint, shared by the http and stream modules. */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <openssl/sha.h>
#include "ngx_ssl_ja4.h"
#include "ngx_ssl_ja4_client_hello.h"

// CONSTANTS
#define SSL3_VERSION_INT    0x0300
#define TLS1_VERSION_INT    0x0301
#define TLS1_1_VERSION_INT  0x0302
#define TLS1_2_VERSION_INT  0x0303
#define TLS1_3_VERSION_INT  0x0304
#define DTLS1_VERSION_INT   0xFEFF
#define DTLS1_2_VERSION_INT 0xFEFD
#define QUICV1_VERSION_INT  0x0001

/**
 * Grease values to be ignored.
 */
static const char *GREASE[] = {
    "0a0a",
    "1a1a",
    "2a2a",
    "3a3a",
    "4a4a",
    "5a5a",
    "6a6a",
    "7a7a",
    "8a8a",
    "9a9a",
    "aaaa",
    "baba",
    "caca",
    "dada",
    "eaea",
    "fafa",
};

// TLS extensions that clients might change from request to request
static const char *EXT_IGNORE_DYNAMIC[] = {
    "0029", // PRE_SHARED_KEY, session resumption
    "0015", // PADDING, padding extension not always included
};

static const char *EXT_IGNORE[] = {
    "0010", // ALPN IGNORE
    "0000", // SNI IGNORE
};

// HELPERS

static int ngx_ssl_ja4_is_ext_dynamic(const char *ext)
{
    size_t i;
    for (i = 0; i < (sizeof(EXT_IGNORE_DYNAMIC) / sizeof(EXT_IGNORE_DYNAMIC[0])); ++i)
    {
        if (strcmp(ext, EXT_IGNORE_DYNAMIC[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int ngx_ssl_ja4_is_ext_ignored(const char *ext)
{
    size_t i;
    for (i = 0; i < (sizeof(EXT_IGNORE) / sizeof(EXT_IGNORE[0])); ++i)
    {
        if (strcmp(ext, EXT_IGNORE[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int
ngx_ssl_ja4_is_ext_greased(const char *ext)
{
    size_t i;
    for (i = 0; i < (sizeof(GREASE) / sizeof(GREASE[0])); ++i)
    {
        if (strcmp(ext, GREASE[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int compare_hexes(const void *a, const void *b)
{
    const char *ext_a = *(const char **)a;
    const char *ext_b = *(const char **)b;

    unsigned int hex_a = strtoul(ext_a, NULL, 16);
    unsigned int hex_b = strtoul(ext_b, NULL, 16);

    if (hex_a < hex_b)
        return -1;
    if (hex_a > hex_b)
        return 1;
    return 0;
}

#if (NGX_DEBUG)
static void
ngx_ssl_ja4_detail_print(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    size_t i;

    /* Transport Protocol (QUIC or TCP) */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4: Transport Protocol: %c",
                   ja4->transport);

    /* SNI presence or absence */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4: SNI: %c",
                   ja4->has_sni);

    /* Version */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: Version:  %s", ja4->version);

    /* Ciphers */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: ciphers: length: %d",
                   ja4->ciphers_sz);

    for (i = 0; i < ja4->ciphers_sz; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    cipher: %s",
                       ja4->ciphers[i]);
    }

    // cipher hash
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: cipher hash: %s",
                   ja4->cipher_hash);

    // cipher hash truncated
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: cipher hash truncated: %s",
                   ja4->cipher_hash_truncated);

    // extension hash
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash: %s",
                   ja4->extension_hash);

    // extension hash truncated
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash truncated: %s",
                   ja4->extension_hash_truncated);

    // extension hash no psk
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash no psk: %s",
                   ja4->extension_hash_no_psk);

    // extension hash no psk truncated
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash no psk truncated: %s",
                   ja4->extension_hash_no_psk_truncated);

    /* Extensions */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extensions: length: %d",
                   ja4->extensions_count);

    for (i = 0; i < ja4->extensions_sz; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    extension: %s",
                       ja4->extensions[i]);
    }

    /* Extensions no PSK */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extensions_no_psk: length: %d",
                   ja4->extensions_no_psk_count);

    for (i = 0; i < ja4->extensions_no_psk_count; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    extension_no_psk: %s",
                       ja4->extensions_no_psk[i]);
    }

    // Signature Algorithms
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: sigalgs: length: %d",
                   ja4->sigalgs_sz);

    for (i = 0; i < ja4->sigalgs_sz; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    sigalgs: %s",
                       ja4->sigalgs[i]);
    }

    /* ALPN Values */
    // handle if null
    if (ja4->alpn_first_value == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: ALPN Value: NULL\n");
    }
    else
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: ALPN Value: %s\n",
                       ja4->alpn_first_value);
    }
}
#endif

static ngx_inline ngx_uint_t
ngx_ssl_ja4_is_ascii_alnum(u_char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z'));
}

static void
ngx_ssl_ja4_write_alpn_code(u_char *dst, const char *alpn)
{
    static const u_char hex[] = "0123456789abcdef";

    if (alpn == NULL) {
        dst[0] = '0';
        dst[1] = '0';
        return;
    }

    size_t len = ngx_strlen(alpn);
    if (len == 0) {
        dst[0] = '0';
        dst[1] = '0';
        return;
    }

    u_char first = (u_char) alpn[0];
    u_char last = (u_char) alpn[len - 1];

    if (ngx_ssl_ja4_is_ascii_alnum(first) && ngx_ssl_ja4_is_ascii_alnum(last)) {
        dst[0] = first;
        dst[1] = last;
        return;
    }

    dst[0] = hex[(first >> 4) & 0x0F];
    dst[1] = hex[last & 0x0F];
}

// JA4
int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    SSL *ssl;
    size_t i;
    ngx_ssl_ja4_client_hello_t ch;

    if (!c->ssl) {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked) {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl) {
        return NGX_DECLINED;
    }
#if (NGX_QUIC || NGX_COMPAT)
    ja4->transport = (c->quic) ? 'q' : 't';
#else
    ja4->transport = 't';
#endif
    ja4->has_sni = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name) ? 'd' : 'i';

    if (ngx_ssl_ja4_client_hello(c, pool, &ch) == NGX_ERROR) {
        return NGX_DECLINED;
    }

    ja4->alpn_first_value = ch.first_alpn;


    /* SSLVersion*/

    int client_version_int = SSL_client_version(ssl);
    int max_version_int = ch.version;
    int version_int = 0;

    version_int = (max_version_int) ? max_version_int : client_version_int;

    switch (version_int)
    {
        case SSL3_VERSION_INT:
            ja4->version = "s3";
            break;
        case TLS1_VERSION_INT:
            ja4->version = "10";
            break;
        case TLS1_1_VERSION_INT:
            ja4->version = "11";
            break;
        case TLS1_2_VERSION_INT:
            ja4->version = "12";
            break;
        case TLS1_3_VERSION_INT:
            ja4->version = "13";
            break;
        case QUICV1_VERSION_INT:
            ja4->version = "q1";
            break;
        default:
            ja4->version = "00";
            break;
    }


    /* Cipher suites */

    ja4->ciphers = NULL;
    ja4->ciphers_sz = 0;


    const unsigned char *raw_ciphers = NULL;
    size_t tls_cipher_len = SSL_get0_raw_cipherlist(ssl, &raw_ciphers);
    if (!raw_ciphers || tls_cipher_len < 2) {
        return NGX_DECLINED;
    }

    size_t raw_cipher_count = tls_cipher_len / 2;

    ja4->ciphers = ngx_pnalloc(pool, raw_cipher_count * sizeof(char *));
    if (ja4->ciphers == NULL) {
        return NGX_DECLINED;
    }
    else
    {
        ngx_memset(ja4->cipher_hash, '0', 2 * SHA256_DIGEST_LENGTH);
        ja4->cipher_hash[2 * SHA256_DIGEST_LENGTH] = '\0';
        ngx_memset(ja4->cipher_hash_truncated, '0', 12);
        ja4->cipher_hash_truncated[12] = '\0'; // Null-terminate the truncated hex string
    }

    size_t *k = &ja4->ciphers_sz;
    for (i = 0; i + 1 < tls_cipher_len; i += 2)
    {
        char hex[5];
        u_int16_t id = ((u_int16_t) raw_ciphers[i] << 8) | raw_ciphers[i + 1];

        ngx_sprintf((u_char *)&hex[0], "%04xd", id);
        hex [4] = '\0';
        if (ngx_ssl_ja4_is_ext_greased (hex)) {
            continue;
        }
        ja4->ciphers[*k] = ngx_palloc (pool, 4 + 1);

        if (ja4->ciphers[*k] == NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, -1, "Failed to allocate memory for a ciphers hex string");
            return NGX_ERROR;
        }

        /* hex is 4 chars + NUL; copy only the used portion */
        ngx_memcpy(ja4->ciphers[*k], hex, 5);
        (void)(*k)++;
    }

    qsort(ja4->ciphers, ja4->ciphers_sz, sizeof(char *), compare_hexes);

#if (NGX_DEBUG)
    ngx_log_debug1 (NGX_LOG_DEBUG_EVENT, c->log, 0, "ja4: sorted cipher suites: (%d)", ja4->ciphers_sz);
    for (int i = 0; i < (int) ja4->ciphers_sz; i++) {
        ngx_log_debug2 (NGX_LOG_DEBUG_EVENT, c->log, 0, "-- [%2d]: %s", i, ja4->ciphers[i]);
    }
#endif

    if (!ja4->ciphers || !ja4->ciphers_sz) {
        return NGX_ERROR;
    }

    unsigned char hash_result[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init (&sha256);

    for (i = 0; i < ja4->ciphers_sz; i++)
    {
        SHA256_Update (&sha256, ja4->ciphers[i], strlen(ja4->ciphers[i]));
        if (i < ja4->ciphers_sz - 1) {
            SHA256_Update(&sha256, ",", 1);
        }
    }

    SHA256_Final(hash_result, &sha256);

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&ja4->cipher_hash[i * 2], "%02x", hash_result[i]);
    }
    ja4->cipher_hash[2 * SHA256_DIGEST_LENGTH] = '\0';

    ngx_memcpy (ja4->cipher_hash_truncated, ja4->cipher_hash, 12);
    ja4->cipher_hash_truncated[12] = '\0';


    /* Extensions */

    ja4->extensions = NULL;
    ja4->extensions_sz = 0;
    ja4->extensions_count = 0;

    // extensions_no_psk
    // no need for sz here bc not counting ignored extensions
    ja4->extensions_no_psk = NULL;
    ja4->extensions_no_psk_count = 0;

    if (ch.extensions_sz && ch.extensions)
    {
        ja4->extensions = ngx_pnalloc (pool, ch.extensions_sz * sizeof(char*));
        ja4->extensions_no_psk = ngx_pnalloc (pool, ch.extensions_sz * sizeof(char*));
        if (ja4->extensions == NULL || ja4->extensions_no_psk == NULL) {
            return NGX_ERROR;
        }

        for (i = 0; i < ch.extensions_sz; ++i) {

            if (ngx_ssl_ja4_is_ext_greased (ch.extensions[i])) {
                continue;
            }

            char *ext = (char *)ch.extensions[i];
            size_t ext_len = strlen (ext) + 1;

            ja4->extensions_count++;

            // ignored extensions are only counted, not hashed
            if (ngx_ssl_ja4_is_ext_ignored(ch.extensions[i])) {
                continue;
            }

            // Allocate memory for the extension string and copy it
            ja4->extensions[ja4->extensions_sz] = ngx_pnalloc(pool, ext_len);
            if (ja4->extensions[ja4->extensions_sz] == NULL) {
                ngx_log_error (NGX_LOG_ERR, c->log, -1, "Failed to allocate memory");
                return NGX_ERROR;
            }
            ngx_memcpy(ja4->extensions[ja4->extensions_sz], ext, ext_len);
            ja4->extensions_sz++;

            // for no psk ignored extensions are not counted, not hashed

            // check if the extension is not a PSK extension
            if (ngx_ssl_ja4_is_ext_dynamic(ch.extensions[i])) {
                continue;
            }

            ja4->extensions_no_psk[ja4->extensions_no_psk_count] = ngx_pnalloc(pool, ext_len);

            if (ja4->extensions_no_psk[ja4->extensions_no_psk_count] == NULL) {
                ngx_log_error (NGX_LOG_ERR, c->log, -1, "Failed to allocate memory");
                return NGX_ERROR;
            }
            ngx_memcpy(ja4->extensions_no_psk[ja4->extensions_no_psk_count], ext, ext_len);
            ja4->extensions_no_psk_count++;
        }

        qsort(ja4->extensions, ja4->extensions_sz, sizeof(char *), compare_hexes);
        qsort(ja4->extensions_no_psk, ja4->extensions_no_psk_count, sizeof(char *), compare_hexes);
    }


    /* Signature Algorithms */

    int num_sigalgs = SSL_get_sigalgs (ssl, 0, NULL, NULL, NULL, NULL, NULL);

    ja4->sigalgs = NULL;
    ja4->sigalgs_sz = 0;

    if (num_sigalgs > 0) {

        ja4->sigalgs = ngx_pnalloc(pool, num_sigalgs * sizeof(char *));
        if (ja4->sigalgs == NULL) {
            return NGX_DECLINED;
        }

        for (int i = 0; i < num_sigalgs; ++i) {

            int psign, phash, psignhash;
            unsigned char rsig, rhash;
            SSL_get_sigalgs (ssl, i, &psign, &phash, &psignhash, &rsig, &rhash);

            ja4->sigalgs[i] = ngx_pnalloc(pool, sizeof("0000"));
            if (ja4->sigalgs[i] == NULL) {
                return NGX_DECLINED;
            }

            *ngx_sprintf((u_char *) ja4->sigalgs[i], "%02xd%02xd", rhash, rsig) = '\0';
        }

        ja4->sigalgs_sz = num_sigalgs;
    }

#if (NGX_DEBUG)
    ngx_log_debug1 (NGX_LOG_DEBUG_EVENT, c->log, 0, "ja4: sigalgs (%d): ", ja4->sigalgs_sz);
    for (int i = 0; i < (int) ja4->sigalgs_sz; i++)
        ngx_log_debug2 (NGX_LOG_DEBUG_EVENT, c->log, 0, "-- [%2d]: %s", i, ja4->sigalgs[i]);
#endif

    // generate hash for extensions
    if (ja4->extensions && ja4->extensions_sz)
    {
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        if (SHA256_Init(&sha256) != 1)
        {
            return NGX_DECLINED;
        }

        for (i = 0; i < ja4->extensions_sz; i++)
        {
            SHA256_Update(&sha256, ja4->extensions[i], strlen(ja4->extensions[i]));
            if (i < ja4->extensions_sz - 1)
            {
                SHA256_Update(&sha256, ",", 1);
            }
        }

        if (ja4->sigalgs_sz)
        {
            // add underscore
            SHA256_Update(&sha256, "_", 1);
            for (i = 0; i < ja4->sigalgs_sz; i++)
            {
                SHA256_Update(&sha256, ja4->sigalgs[i], strlen(ja4->sigalgs[i]));
                if (i < ja4->sigalgs_sz - 1)
                {
                    SHA256_Update(&sha256, ",", 1);
                }
            }
        }

        SHA256_Final(hash_result, &sha256);

        // Convert the full hash to hexadecimal format
        char hex_hash[2 * SHA256_DIGEST_LENGTH + 1]; // +1 for null-terminator
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(hex_hash + 2 * i, "%02x", hash_result[i]);
        }
        ngx_memcpy(ja4->extension_hash, hex_hash, 2 * SHA256_DIGEST_LENGTH);
        ja4->extension_hash[2 * SHA256_DIGEST_LENGTH] = '\0';

        // Convert the truncated hash to hexadecimal format
        char hex_hash_truncated[2 * 6 + 1]; // 6 bytes, 2 characters each = 12 characters plus null-terminator
        for (i = 0; i < 6; i++)
        {
            sprintf(hex_hash_truncated + 2 * i, "%02x", hash_result[i]);
        }
        // Copy the first 6 bytes (12 characters) for the truncated hash
        ngx_memcpy(ja4->extension_hash_truncated, hex_hash_truncated, 12);
        ja4->extension_hash_truncated[12] = '\0';
    }
    else
    {
        ngx_memset(ja4->extension_hash, '0', 2 * SHA256_DIGEST_LENGTH);
        ja4->extension_hash[2 * SHA256_DIGEST_LENGTH] = '\0';
        ngx_memset(ja4->extension_hash_truncated, '0', 12);
        ja4->extension_hash_truncated[12] = '\0'; // Null-terminate the truncated hex string
    }

    // generate hash for extensions_no_psk
    // also doesn't include signature algorithms
    if (ja4->extensions_no_psk && ja4->extensions_no_psk_count)
    {
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256_psk;
        if (SHA256_Init(&sha256_psk) != 1)
        {
            return NGX_DECLINED;
        }

        for (i = 0; i < ja4->extensions_no_psk_count; i++)
        {
            SHA256_Update(&sha256_psk, ja4->extensions_no_psk[i], strlen(ja4->extensions_no_psk[i]));
            // add comma separator if not last val
            if (i < ja4->extensions_no_psk_count - 1)
            {
                SHA256_Update(&sha256_psk, ",", 1);
            }
        }

        SHA256_Final(hash_result, &sha256_psk);

        // Convert the full hash to hexadecimal (human readable) format
        char hex_hash[2 * SHA256_DIGEST_LENGTH + 1]; // +1 for null-terminator
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(hex_hash + 2 * i, "%02x", hash_result[i]);
        }
        ngx_memcpy(ja4->extension_hash_no_psk, hex_hash, 2 * SHA256_DIGEST_LENGTH);
        ja4->extension_hash_no_psk[2 * SHA256_DIGEST_LENGTH] = '\0';

        // Convert the truncated hash to hexadecimal format
        char hex_hash_truncated[2 * 6 + 1]; // 6 bytes, 2 characters each = 12 characters plus null-terminator
        for (i = 0; i < 6; i++)
        {
            sprintf(hex_hash_truncated + 2 * i, "%02x", hash_result[i]);
        }
        // Copy the first 6 bytes (12 characters) for the truncated hash
        ngx_memcpy(ja4->extension_hash_no_psk_truncated, hex_hash_truncated, 12);
        ja4->extension_hash_no_psk_truncated[12] = '\0';
    }
    else
    {
        ngx_memset(ja4->extension_hash_no_psk, '0', 2 * SHA256_DIGEST_LENGTH);
        ja4->extension_hash_no_psk[2 * SHA256_DIGEST_LENGTH] = '\0';
        ngx_memset(ja4->extension_hash_no_psk_truncated, '0', 12);
        ja4->extension_hash_no_psk_truncated[12] = '\0'; // Null-terminate the truncated hex string
    }
    return NGX_OK;
}

void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // this function uses stuff on the ja4 struct to create a fingerprint
    // Calculate memory requirements for output
    size_t len = 256; // Big enough

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }
    out->len = len;

    size_t cur = 0;

    out->data[cur++] = ja4->transport;

    // 2 character TLS version
    memcpy(out->data + cur, ja4->version, 2);
    cur += 2;

    // SNI = d, no SNI = i
    out->data[cur++] = ja4->has_sni;

    // 2 character count of ciphers
    size_t ciphers_sz = ja4->ciphers_sz;
    if (ciphers_sz > 99) {
        ciphers_sz = 99;
    }
    ngx_snprintf (out->data + cur, 3, "%02d", ciphers_sz);
    cur += 2;

    // 2 character count of extensions
    ngx_snprintf (out->data + cur, 3, "%02d", ja4->extensions_count);
    cur += 2;

    // Add ALPN first/last value per JA4 spec
    ngx_ssl_ja4_write_alpn_code(out->data + cur, ja4->alpn_first_value);
    cur += 2;


    // Add underscore
    out->data[cur++] = '_';

    // Add cipher hash, 12 characters for truncated hash
    ngx_snprintf(out->data + cur, 13, "%s", ja4->cipher_hash_truncated);
    cur += 12;

    // Add underscore
    out->data[cur++] = '_';

    // Add extension hash, 12 characters for truncated hash
    ngx_snprintf(out->data + cur, 13, "%s", ja4->extension_hash_truncated);
    cur += 12;

    // Null-terminate the string
    out->data[cur] = '\0';
    out->len = cur;

#if (NGX_DEBUG)
    ngx_ssl_ja4_detail_print(pool, ja4);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp: [%V]\n", out);
#endif
}

// JA4 STRING
void ngx_ssl_ja4_fp_string(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // This function calculates the ja4 fingerprint but it doesn't hash extensions and ciphers
    // Instead, it just comma separates them
    size_t i;
    char **sigalgs_copy = malloc(ja4->sigalgs_sz * sizeof(char *));
    for (i = 0; i < ja4->sigalgs_sz; ++i)
    {
        sigalgs_copy[i] = strdup(ja4->sigalgs[i]);
    }

    // Initial size calculation
    // Base size for fixed elements: 't', version (2 chars), has_sni, ciphers_sz (2 chars), extensions_sz (2 chars),
    // alpn (2 chars), separators ('_' x3), null-terminator
    size_t len = 1 + 2 + 1 + 2 + 2 + 2 + 3 + 1;
    // Dynamic size for variable elements: ciphers, extensions, signature algorithms
    for (i = 0; i < ja4->ciphers_sz; ++i)
    {
        len += strlen(ja4->ciphers[i]) + 1; // strlen of cipher + comma
    }
    for (i = 0; i < ja4->extensions_sz; ++i)
    {
        len += strlen(ja4->extensions[i]) + 1; // strlen of extension + comma
    }
    for (i = 0; i < ja4->sigalgs_sz; ++i)
    {
        len += strlen(ja4->sigalgs[i]) + 1; // strlen of sigalg + comma
    }

    len += 256; // Safety padding

    // Allocate memory based on calculated size
    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }

    size_t cur = 0;

    // t for TCP
    out->data[cur++] = ja4->transport;

    // 2 character TLS version
    if (ja4->version == NULL)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 3, "%s", ja4->version);
    }
    cur += 2;

    // SNI = d, no SNI = i
    out->data[cur++] = ja4->has_sni;

    // 2 character count of ciphers
    size_t ciphers_sz = ja4->ciphers_sz;
    if (ciphers_sz == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        if (ciphers_sz > 99) {
            ciphers_sz = 99;
        }
        ngx_snprintf(out->data + cur, 3, "%02zu", ciphers_sz);
    }
    cur += 2;

    // 2 character count of extensions
    ngx_snprintf (out->data + cur, 3, "%02d", ja4->extensions_count);
    cur += 2;

    // Add 2 characters for the ALPN ja4->alpn_first_value
    ngx_ssl_ja4_write_alpn_code(out->data + cur, ja4->alpn_first_value);
    cur += 2;

    // Separator
    out->data[cur++] = '_';

    // Add ciphers
    if (ja4->ciphers_sz > 0)
    {
        for (i = 0; i < ja4->ciphers_sz; ++i)
        {
            size_t n = ngx_snprintf(out->data + cur, strlen(ja4->ciphers[i]) + 2, "%s,", ja4->ciphers[i]) - out->data - cur;
            cur += n;
        }
        cur--; // Remove the trailing comma
    }

    // Separator
    out->data[cur++] = '_';

    // Add extensions
    if (ja4->extensions_sz > 0)
    {
        for (i = 0; i < ja4->extensions_sz; ++i)
        {
            size_t n = ngx_snprintf(out->data + cur, strlen(ja4->extensions[i]) + 2, "%s,", ja4->extensions[i]) - out->data - cur;
            cur += n;
        }
        cur--; // Remove the trailing comma
    }

    // Add signature algorithms
    if (ja4->sigalgs_sz > 0)
    {
        out->data[cur++] = '_'; // Add separator only if signature algorithms are present
        for (i = 0; i < ja4->sigalgs_sz; ++i)
        {
            size_t n = ngx_snprintf(out->data + cur, strlen(sigalgs_copy[i]) + 2, "%s,", sigalgs_copy[i]) - out->data - cur;
            cur += n;
        }
        cur--; // Remove the trailing comma
    }

    for (i = 0; i < ja4->sigalgs_sz; ++i)
    {
        free(sigalgs_copy[i]);
    }
    free(sigalgs_copy);

    // Null-terminate the string
    out->data[cur] = '\0';
    out->len = cur;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp_string: [%V]\n", out);
#endif
}

// JA4ONE
void ngx_ssl_ja4one_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // this function uses stuff on the ja4 struct to create a ja4one fingerprint
    // Calculate memory requirements for output
    size_t len = 256; // Big enough

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }
    out->len = len;

    size_t cur = 0;

    // q for QUIC or t for TCP
    // Assuming is_quic is a boolean.
    // out->data[cur++] = (ja4->is_quic) ? 'q' : 't';
    // TODO: placeholder
    out->data[cur++] = 't';

    // 2 character TLS version
    memcpy(out->data + cur, ja4->version, 2);
    cur += 2;

    // SNI = d, no SNI = i
    out->data[cur++] = ja4->has_sni;

    // 2 character count of ciphers
    size_t ciphers_sz = ja4->ciphers_sz;
    if (ciphers_sz == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        if (ciphers_sz > 99) {
            ciphers_sz = 99;
        }
        ngx_snprintf(out->data + cur, 3, "%02zu", ciphers_sz);
    }
    cur += 2;

    // 2 character count of extensions
    ngx_snprintf(out->data + cur, 3, "%02d", ja4->extensions_no_psk_count);
    cur += 2;

    // Add ALPN first/last value per JA4 spec
    ngx_ssl_ja4_write_alpn_code(out->data + cur, ja4->alpn_first_value);
    cur += 2;

    // Add underscore
    out->data[cur++] = '_';

    // Add cipher hash, 12 characters for truncated hash
    ngx_snprintf(out->data + cur, 13, "%s", ja4->cipher_hash_truncated);
    cur += 12;

    // Add underscore
    out->data[cur++] = '_';

    // Add extension hash, 12 characters for truncated hash
    ngx_snprintf(out->data + cur, 13, "%s", ja4->extension_hash_no_psk_truncated);
    cur += 12;

    // Null-terminate the string
    out->data[cur] = '\0';
    out->len = cur;

#if (NGX_DEBUG)
    ngx_ssl_ja4_detail_print(pool, ja4);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp: [%V]\n", out);
#endif
}

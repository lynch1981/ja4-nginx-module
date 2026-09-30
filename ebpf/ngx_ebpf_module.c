
/*
 * nginx eBPF loader: upstream SYN-ACK capture.
 *
 * The master loads the BPF object and attaches it to Netfilter PREROUTING and
 * POSTROUTING; workers inherit the map descriptors.  A connection registers
 * its socket cookie before connect(), consumes the captured SYN-ACK headers
 * once the socket is established, and unregisters when it is closed.  One
 * worker at a time holds a lease to sweep entries left behind by crashes.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <sys/mman.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <linux/netfilter.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ngx_ebpf_module.h"
#include "ngx_ebpf.h"
#include "ngx_ebpf.skel.h"


#define NGX_EBPF_LINKS          4       /* {PRE,POST}ROUTING x {IPv4,IPv6} */

/*
 * Netfilter refuses a second BPF program at the same hook and priority, so
 * each capture-enabled process in a network namespace takes the next free
 * one: INT_MIN + 1, + 2, ... and INT_MAX - 1, - 2, ...
 */
#define NGX_EBPF_PRIORITIES     64
#define NGX_EBPF_SWEEP_MSEC     1000
#define NGX_EBPF_LEASE_SEC      3

/* Sweep a sixty-fourth of each map per tick. */
#define NGX_EBPF_SWEEP_CONN     (SYNACK_CONNECTIONS / 64)
#define NGX_EBPF_SWEEP_EXPECT   (SYNACK_EXPECTATIONS / 64)


typedef struct {
    ngx_flag_t                  enabled;
} ngx_ebpf_conf_t;


typedef void (*ngx_ebpf_expire_pt)(int fd, void *key, uint64_t now);

typedef struct {
    int                        *fd;
    size_t                      key_size;
    ngx_uint_t                  budget;
    ngx_ebpf_expire_pt          expire;
    ngx_uint_t                  valid;
    u_char                      cursor[sizeof(struct synack_key)];
} ngx_ebpf_sweeper_t;


static void *ngx_ebpf_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_ebpf_init(ngx_cycle_t *cycle);
static void ngx_ebpf_exit(ngx_cycle_t *cycle);
static int ngx_ebpf_libbpf_print(enum libbpf_print_level level,
    const char *fmt, va_list args);
static uint64_t ngx_ebpf_now(void);
static void ngx_ebpf_remove(uint64_t cookie, ngx_uint_t consumed);
static void ngx_ebpf_sweep(ngx_event_t *ev);
static ngx_uint_t ngx_ebpf_take_lease(uint64_t now);
static void ngx_ebpf_sweep_map(ngx_ebpf_sweeper_t *sw, uint64_t now);
static void ngx_ebpf_expire_conn(int fd, void *key, uint64_t now);
static void ngx_ebpf_expire_capture(int fd, void *key, uint64_t now);
static void ngx_ebpf_expire_expect(int fd, void *key, uint64_t now);


static ngx_core_module_t  ngx_ebpf_module_ctx = {
    ngx_string("ebpf"),
    ngx_ebpf_create_conf,
    NULL
};


ngx_module_t  ngx_ebpf_module = {
    NGX_MODULE_V1,
    &ngx_ebpf_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_ebpf_init,                         /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_ebpf_exit,                         /* exit process */
    ngx_ebpf_exit,                         /* exit master */
    NGX_MODULE_V1_PADDING
};


/* Process lifetime, deliberately independent of configuration-cycle pools. */

static struct ngx_ebpf     *ngx_ebpf_skel;
static struct bpf_link     *ngx_ebpf_links[NGX_EBPF_LINKS];
static int                  ngx_ebpf_conn_fd = -1;
static int                  ngx_ebpf_expect_fd = -1;
static int                  ngx_ebpf_capture_fd = -1;
static ngx_uint_t           ngx_ebpf_started;
static ngx_log_t           *ngx_ebpf_log;
static ngx_uint_t           ngx_ebpf_quiet;
static uint64_t            *ngx_ebpf_lease;
static uint64_t            *ngx_ebpf_stats;
static ngx_event_t          ngx_ebpf_timer;
static ngx_connection_t     ngx_ebpf_timer_connection;


static ngx_ebpf_sweeper_t  ngx_ebpf_sweepers[] = {
    { &ngx_ebpf_conn_fd, sizeof(uint64_t), NGX_EBPF_SWEEP_CONN,
      ngx_ebpf_expire_conn, 0, { 0 } },
    { &ngx_ebpf_capture_fd, sizeof(uint64_t), NGX_EBPF_SWEEP_CONN,
      ngx_ebpf_expire_capture, 0, { 0 } },
    { &ngx_ebpf_expect_fd, sizeof(struct synack_key), NGX_EBPF_SWEEP_EXPECT,
      ngx_ebpf_expire_expect, 0, { 0 } }
};


#define ngx_ebpf_count(stat)                                                  \
    (void) __sync_fetch_and_add(&ngx_ebpf_stats[stat], 1)


static void *
ngx_ebpf_create_conf(ngx_cycle_t *cycle)
{
    return ngx_pcalloc(cycle->pool, sizeof(ngx_ebpf_conf_t));
}


ngx_int_t
ngx_ebpf_require(ngx_conf_t *cf)
{
    ngx_ebpf_conf_t  *conf;

    if (ngx_ebpf_started && ngx_ebpf_skel == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "tcp_save_synack: enabling capture requires "
                           "a restart");
        return NGX_ERROR;
    }

    conf = (ngx_ebpf_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                            ngx_ebpf_module);
    conf->enabled = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_ebpf_init(ngx_cycle_t *cycle)
{
    ngx_err_t                   err;
    ngx_uint_t                  i, n, skipped;
    ngx_ebpf_conf_t            *conf;
    struct bpf_link            *link;
    struct bpf_program         *prog;
    struct bpf_netfilter_opts   opts;

    if (ngx_test_config || ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_OK;
    }

    conf = (ngx_ebpf_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_ebpf_module);

    if (ngx_ebpf_started) {

        /* reload: keep what the first cycle created */

        if (conf->enabled && ngx_ebpf_skel == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "tcp_save_synack: enabling capture requires "
                          "a restart");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    ngx_ebpf_started = 1;

    if (!conf->enabled) {
        return NGX_OK;
    }

    /* libbpf prints to stderr by default; keep its detail in the error log */

    ngx_ebpf_log = cycle->log;
    (void) libbpf_set_print(ngx_ebpf_libbpf_print);

    ngx_ebpf_skel = ngx_ebpf__open_and_load();
    if (ngx_ebpf_skel == NULL) {
        goto failed;
    }

    ngx_ebpf_conn_fd = bpf_map__fd(ngx_ebpf_skel->maps.synack_conn);
    ngx_ebpf_expect_fd = bpf_map__fd(ngx_ebpf_skel->maps.synack_expect);
    ngx_ebpf_capture_fd = bpf_map__fd(ngx_ebpf_skel->maps.synack_capture);

    ngx_ebpf_stats = mmap(NULL, SYNACK_STAT_COUNT * sizeof(uint64_t),
                          PROT_READ|PROT_WRITE, MAP_SHARED,
                          bpf_map__fd(ngx_ebpf_skel->maps.synack_stats), 0);
    if (ngx_ebpf_stats == MAP_FAILED) {
        ngx_ebpf_stats = NULL;
        goto failed;
    }

    /* both PREROUTING links precede either POSTROUTING link */

    skipped = 0;

    for (i = 0; i < NGX_EBPF_LINKS; i++) {
        ngx_memzero(&opts, sizeof(struct bpf_netfilter_opts));
        opts.sz = sizeof(struct bpf_netfilter_opts);
        opts.pf = (i & 1) ? AF_INET6 : AF_INET;

        if (i < 2) {
            prog = ngx_ebpf_skel->progs.synack_in;
            opts.hooknum = NF_INET_PRE_ROUTING;

        } else {
            prog = ngx_ebpf_skel->progs.synack_out;
            opts.hooknum = NF_INET_POST_ROUTING;
        }

        link = NULL;
        err = NGX_EBUSY;

        for (n = 0; n < NGX_EBPF_PRIORITIES; n++) {
            opts.priority = (i < 2) ? INT_MIN + 1 + (int) n
                                    : INT_MAX - 1 - (int) n;

            /* a taken priority is expected; libbpf would warn each time */

            ngx_ebpf_quiet = 1;
            link = bpf_program__attach_netfilter(prog, &opts);
            err = ngx_errno;
            ngx_ebpf_quiet = 0;

            if (link != NULL && libbpf_get_error(link) == 0) {
                break;
            }

            link = NULL;

            if (err != NGX_EBUSY) {
                break;
            }
        }

        if (link == NULL) {
            ngx_set_errno(err);
            goto failed;
        }

        ngx_ebpf_links[i] = link;
        skipped = ngx_max(skipped, n);
    }

    if (skipped) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "tcp_save_synack: other processes capture in this "
                      "network namespace; attached %ui hook priorities "
                      "further in", skipped);
    }

    ngx_ebpf_lease = mmap(NULL, sizeof(uint64_t), PROT_READ|PROT_WRITE,
                          MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (ngx_ebpf_lease == MAP_FAILED) {
        ngx_ebpf_lease = NULL;
        goto failed;
    }

    *ngx_ebpf_lease = 0;

    ngx_ebpf_log = NULL;

    return NGX_OK;

failed:

    err = ngx_errno;

    if (err == NGX_EBUSY) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                      "tcp_save_synack: all %d Netfilter hook priorities "
                      "for capture are taken by other processes in this "
                      "network namespace", NGX_EBPF_PRIORITIES);

    } else if (err == NGX_EPERM || err == NGX_EACCES) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                      "tcp_save_synack: cannot load the BPF capture "
                      "programs; the master process needs root, or "
                      "CAP_BPF, CAP_PERFMON and CAP_NET_ADMIN");

    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                      "tcp_save_synack: cannot initialize Netfilter BPF "
                      "capture (requires Linux 6.4+ with kernel BTF)");
    }

    ngx_ebpf_exit(cycle);

    ngx_ebpf_log = NULL;

    return NGX_ERROR;
}


/*
 * libbpf warnings are logged at the notice level: the emerg message above
 * reports the failure, and "error_log ... notice" shows libbpf's reasons.
 * Attach attempts are quiet: a taken priority is expected, and the emerg
 * message carries the errno of the last attempt.
 */

static int
ngx_ebpf_libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list args)
{
    int         n;
    char        buf[NGX_MAX_ERROR_STR];
    ngx_log_t  *log;

    if (ngx_ebpf_quiet) {
        return 0;
    }

    log = ngx_ebpf_log ? ngx_ebpf_log : ngx_cycle->log;

    n = vsnprintf(buf, sizeof(buf), fmt, args);
    if (n < 0) {
        return 0;
    }

    if (n > (int) sizeof(buf) - 1) {
        n = sizeof(buf) - 1;
    }

    while (n > 0 && buf[n - 1] == '\n') {
        n--;
    }

    if (level == LIBBPF_WARN) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "%*s", (size_t) n, buf);

    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0, "%*s",
                       (size_t) n, buf);
    }

    return 0;
}


ngx_int_t
ngx_ebpf_worker_init(ngx_cycle_t *cycle)
{
    if (ngx_ebpf_skel == NULL
        || (ngx_process != NGX_PROCESS_WORKER
            && ngx_process != NGX_PROCESS_SINGLE))
    {
        return NGX_OK;
    }

    ngx_memzero(&ngx_ebpf_timer, sizeof(ngx_event_t));

    ngx_ebpf_timer_connection.fd = (ngx_socket_t) -1;

    ngx_ebpf_timer.handler = ngx_ebpf_sweep;
    ngx_ebpf_timer.data = &ngx_ebpf_timer_connection;
    ngx_ebpf_timer.log = cycle->log;
    ngx_ebpf_timer.cancelable = 1;

    ngx_add_timer(&ngx_ebpf_timer, NGX_EBPF_SWEEP_MSEC);

    return NGX_OK;
}


static void
ngx_ebpf_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    /*
     * Close inherited references only; never BPF_LINK_DETACH a link that
     * other processes share.  These links are not in skel->links, so
     * ngx_ebpf__destroy() does not touch them.
     */

    for (i = 0; i < NGX_EBPF_LINKS; i++) {
        if (ngx_ebpf_links[i]) {
            (void) close(bpf_link__fd(ngx_ebpf_links[i]));
            ngx_ebpf_links[i] = NULL;
        }
    }

    if (ngx_ebpf_stats) {
        (void) munmap(ngx_ebpf_stats, SYNACK_STAT_COUNT * sizeof(uint64_t));
        ngx_ebpf_stats = NULL;
    }

    if (ngx_ebpf_skel) {
        ngx_ebpf__destroy(ngx_ebpf_skel);
        ngx_ebpf_skel = NULL;
    }

    ngx_ebpf_conn_fd = -1;
    ngx_ebpf_expect_fd = -1;
    ngx_ebpf_capture_fd = -1;

    if (ngx_ebpf_lease) {
        (void) munmap(ngx_ebpf_lease, sizeof(uint64_t));
        ngx_ebpf_lease = NULL;
    }
}


static uint64_t
ngx_ebpf_now(void)
{
    struct timespec  ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        return 0;
    }

    return (uint64_t) ts.tv_sec * SYNACK_NSEC_PER_SEC + ts.tv_nsec;
}


void
ngx_connection_register_synack(ngx_connection_t *c, struct sockaddr *sa,
    ngx_flag_t enabled)
{
    int                        rc;
    uint64_t                   cookie;
    socklen_t                  len;
    struct synack_connection   state;

    static ngx_msec_t          last_warning;

    if (!enabled
        || ngx_ebpf_conn_fd < 0
        || c->type != SOCK_STREAM
        || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6))
    {
        return;
    }

    c->synack_enabled = 1;

    /* the cookie is assigned on first use, so it must precede connect() */

    len = sizeof(uint64_t);

    if (getsockopt(c->fd, SOL_SOCKET, SO_COOKIE, &cookie, &len) == -1
        || len != sizeof(uint64_t)
        || cookie == 0)
    {
        ngx_ebpf_count(SYNACK_STAT_REGISTER_FAILED);
        return;
    }

    ngx_memzero(&state, sizeof(struct synack_connection));
    state.deadline = ngx_ebpf_now() + SYNACK_PENDING_NS;

    rc = bpf_map_update_elem(ngx_ebpf_conn_fd, &cookie, &state, BPF_NOEXIST);

    if (rc < 0) {
        ngx_ebpf_count(SYNACK_STAT_REGISTER_FAILED);

        /* the stats counter is exact; the log is limited to one per second */

        if (ngx_current_msec - last_warning >= 1000) {
            last_warning = ngx_current_msec;
            ngx_log_error(NGX_LOG_WARN, c->log, -rc,
                          "tcp_save_synack: registration failed, "
                          "metadata unavailable");
        }

        return;
    }

    c->synack_cookie = cookie;
}


void
ngx_connection_save_synack(ngx_connection_t *c)
{
    int                    rc;
    u_char                *buf;
    uint64_t               now, cookie;
    socklen_t              len;
    struct tcp_info        info;
    struct synack_record   record;

    if (!c->synack_enabled
        || c->synack_processed
        || c->synack_cookie == 0
        || c->pool == NULL
        || ngx_ebpf_capture_fd < 0)
    {
        return;
    }

    /* confirm the handshake completed before consuming the capture */

    ngx_memzero(&info, sizeof(struct tcp_info));
    len = sizeof(struct tcp_info);

    if (getsockopt(c->fd, IPPROTO_TCP, TCP_INFO, &info, &len) == -1
        || (info.tcpi_state != TCP_ESTABLISHED
            && info.tcpi_state != TCP_CLOSE_WAIT))
    {
        return;
    }

    /* one attempt: from here on the record is consumed or absent */

    c->synack_processed = 1;

    cookie = c->synack_cookie;

    rc = bpf_map_lookup_and_delete_elem(ngx_ebpf_capture_fd, &cookie,
                                        &record);

    /*
     * The registration has no further use either way: a successful capture
     * has already deleted it in BPF, and a missed one can no longer happen.
     */

    ngx_connection_cleanup_synack(c);

    if (rc < 0) {
        if (rc != -ENOENT) {
            ngx_ebpf_count(SYNACK_STAT_HANDOFF_ERROR);
        }

        return;
    }

    now = ngx_ebpf_now();

    if (record.version != SYNACK_VERSION
        || record.length < 40
        || record.length > SYNACK_MAX_HEADERS
        || record.timestamp > now
        || now - record.timestamp >= SYNACK_CAPTURE_NS)
    {
        ngx_ebpf_count(SYNACK_STAT_INVALID_RECORD);
        return;
    }

#if (NGX_SYNACK_TEST)
    buf = getenv("NGX_SYNACK_TEST_ALLOC_FAIL")
          ? NULL : ngx_pnalloc(c->pool, record.length);
#else
    buf = ngx_pnalloc(c->pool, record.length);
#endif

    if (buf == NULL) {
        ngx_ebpf_count(SYNACK_STAT_ALLOC_FAILED);
        return;
    }

    ngx_memcpy(buf, record.headers, record.length);

    c->saved_synack.data = buf;
    c->saved_synack.len = record.length;

#if (NGX_SYNACK_TEST)
    {
    int                        present;
    u_char                     hex[SYNACK_MAX_HEADERS * 2];
    ngx_str_t                  raw;
    struct synack_record       retained;
    struct synack_connection   state;

    present = bpf_map_lookup_elem(ngx_ebpf_capture_fd, &cookie, &retained)
              == 0
              || bpf_map_lookup_elem(ngx_ebpf_conn_fd, &cookie, &state) == 0;

    raw.data = hex;
    raw.len = ngx_hex_dump(hex, c->saved_synack.data, c->saved_synack.len)
              - hex;

    ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                  "synack test handoff: cookie=%uL len=%uz kernel=%d raw=%V",
                  cookie, c->saved_synack.len, present, &raw);
    }
#endif
}


void
ngx_connection_cleanup_synack(ngx_connection_t *c)
{
    if (c->synack_cookie == 0 || ngx_ebpf_conn_fd < 0) {
        return;
    }

    ngx_ebpf_remove(c->synack_cookie, c->synack_processed);

    c->synack_cookie = 0;
}


/*
 * "consumed" means the connection has already taken (or discarded) its
 * capture record, so only the registration is left to delete.
 */

static void
ngx_ebpf_remove(uint64_t cookie, ngx_uint_t consumed)
{
    ngx_uint_t                  i;
    struct synack_connection    state;
    struct synack_expectation   owner;

    /* a completed capture has already removed the keys it owned in BPF */

    if (bpf_map_lookup_and_delete_elem(ngx_ebpf_conn_fd, &cookie, &state) == 0
        && state.phase != SYNACK_COMPLETE)
    {
        for (i = 0; i < state.count && i < SYNACK_MAX_ALIASES; i++) {

            if (bpf_map_lookup_elem(ngx_ebpf_expect_fd, &state.keys[i],
                                    &owner)
                == 0
                && owner.cookie == cookie
                && !owner.ambiguous)
            {
                (void) bpf_map_delete_elem(ngx_ebpf_expect_fd,
                                           &state.keys[i]);
            }
        }
    }

    if (!consumed) {
        (void) bpf_map_delete_elem(ngx_ebpf_capture_fd, &cookie);
    }
}


static void
ngx_ebpf_sweep(ngx_event_t *ev)
{
    uint64_t    now;
    ngx_uint_t  i;

    now = ngx_ebpf_now();

    if (ngx_ebpf_take_lease(now)) {
        for (i = 0; i < sizeof(ngx_ebpf_sweepers)
                        / sizeof(ngx_ebpf_sweeper_t); i++)
        {
            ngx_ebpf_sweep_map(&ngx_ebpf_sweepers[i], now);
        }
    }

    ngx_add_timer(ev, NGX_EBPF_SWEEP_MSEC);
}


/*
 * The lease word holds the expiry second in the high 32 bits and the owner
 * pid in the low 32 bits.  The owner renews it on every tick; any worker may
 * take it over once it has expired, e.g. after the owner crashed.
 */

static ngx_uint_t
ngx_ebpf_take_lease(uint64_t now)
{
    uint64_t  lease, wanted, sec;

    sec = now / SYNACK_NSEC_PER_SEC;
    lease = *ngx_ebpf_lease;
    wanted = ((sec + NGX_EBPF_LEASE_SEC) << 32) | (uint32_t) ngx_pid;

    if ((uint32_t) lease != (uint32_t) ngx_pid && (lease >> 32) > sec) {
        return 0;
    }

    return __sync_bool_compare_and_swap(ngx_ebpf_lease, lease, wanted);
}


/*
 * Visits up to sw->budget keys per tick and resumes from the saved cursor on
 * the next tick; after the last key the walk restarts from the first one.
 */

static void
ngx_ebpf_sweep_map(ngx_ebpf_sweeper_t *sw, uint64_t now)
{
    int         more;
    u_char      current[sizeof(struct synack_key)];
    u_char      next[sizeof(struct synack_key)];
    ngx_uint_t  i;

    for (i = 0; i < sw->budget; i++) {

        if (!sw->valid
            && bpf_map_get_next_key(*sw->fd, NULL, sw->cursor) != 0)
        {
            break;
        }

        ngx_memcpy(current, sw->cursor, sw->key_size);

        more = bpf_map_get_next_key(*sw->fd, current, next) == 0;

        sw->expire(*sw->fd, current, now);

        if (more) {
            ngx_memcpy(sw->cursor, next, sw->key_size);
        }

        sw->valid = more;

        if (!more) {
            break;
        }
    }
}


static void
ngx_ebpf_expire_conn(int fd, void *key, uint64_t now)
{
    uint64_t                   cookie;
    struct synack_connection   state;

    cookie = *(uint64_t *) key;

    if (bpf_map_lookup_elem(fd, &cookie, &state) == 0
        && state.deadline <= now)
    {
        ngx_ebpf_count(SYNACK_STAT_EXPIRED);
        ngx_ebpf_remove(cookie, 0);
    }
}


static void
ngx_ebpf_expire_capture(int fd, void *key, uint64_t now)
{
    struct synack_record  record;

    if (bpf_map_lookup_elem(fd, key, &record) == 0
        && now >= record.timestamp
        && now - record.timestamp >= SYNACK_CAPTURE_NS)
    {
        ngx_ebpf_count(SYNACK_STAT_EXPIRED);
        (void) bpf_map_delete_elem(fd, key);
    }
}


static void
ngx_ebpf_expire_expect(int fd, void *key, uint64_t now)
{
    struct synack_expectation  expectation;

    if (bpf_map_lookup_elem(fd, key, &expectation) == 0
        && expectation.deadline <= now)
    {
        ngx_ebpf_count(SYNACK_STAT_EXPIRED);
        (void) bpf_map_delete_elem(fd, key);
    }
}

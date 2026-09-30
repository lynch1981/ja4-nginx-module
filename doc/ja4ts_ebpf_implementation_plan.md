# Nginx-owned SYN-ACK capture and JA4TS

## Implementation

Capture uses the optional static core addon in `ebpf/` (the eBPF loader, with
kernel-side sources in `ebpf/bpf/`) and the independent
`patches/nginx-tcp-save-synack.patch`. The compiled CO-RE object is embedded in
the committed libbpf skeleton `ebpf/ngx_ebpf.skel.h`, so building Nginx needs
libbpf but no BPF toolchain. `ebpf/gen-skel.sh` regenerates it after BPF changes
(clang, bpftool, kernel BTF; `bpftool gen object` drops DWARF and keeps BTF). The
skeleton records a sha256 of its inputs, and CI runs `gen-skel.sh --check` to
reject a stale one.
The HTTP JA4 module only formats request-owned raw headers; it neither loads BPF nor retrieves kernel records.
The former sockops/partial-tuple proposal is superseded by this design.

```nginx
tcp_save_synack on; # default: off
```

The directive accepts `on|off` in HTTP `http`, `server`, and `location` contexts.
Ordinary inheritance applies. Main configuration, `upstream` and `stream` contexts
reject it. Named upstreams, direct peers,
and dynamically resolved peers use the same socket path. UDP, Unix sockets and
QUIC do not register. With the core patch but without the addon, `off` is valid
and `on` fails configuration validation with a build requirement diagnostic.

The effective setting is latched on each newly created TCP connection. Reusing
a keepalive connection never starts capture. An off request always sees empty
variables, including when a shared pool returns a previously captured connection.
An on request cannot reconstruct an uncaptured keepalive connection's handshake.

## Registration and correlation

Before `connect()`, Nginx obtains `SO_COOKIE` and inserts the cookie in the
connection map. Failures only lose optional metadata. No sockops, conntrack,
cgroup enrollment, interface discovery, bpffs pinning, external service, or
production reader executable is required.

The master attaches both PREROUTING programs before either POSTROUTING program,
in its own network namespace. The default priorities are `INT_MIN + 1` and
`INT_MAX - 1`, respectively. Netfilter allows one BPF program per hook and
priority, so a process that finds them taken (another capture-enabled nginx,
or the old master during a binary upgrade) uses the next free ones inward, up
to 64. Every path returns `NF_ACCEPT` and leaves bytes alone.

POSTROUTING processes SYN packets with ACK/RST clear. It obtains the socket from
hook state (falling back to `skb->sk`) and lets every other packet through
before the map lookup, reading two socket fields with CO-RE: the state (only
`SYN_SENT` sends SYNs; `CLOSE` also passes, for unconnected raw and UDP
sockets) and the cookie (zero until requested, which nginx does before
registering). It then requires a live pending registration. For packet
sequence S, it deduplicates up to two incoming expectation keys:

| Tuple | ACK |
| --- | --- |
| Reversed outgoing packet tuple | S + 1 |
| Reversed original socket tuple | S + 1 |

nginx does not use TCP Fast Open on upstream connections, so SYN data is never
expected and a SYN-ACK acknowledging it (S + 1 + N) does not match.

ACK arithmetic wraps modulo 2^32. The packet alias handles replies before reverse
NAT, while the socket alias handles same-namespace loopback replies after reverse
NAT in OUTPUT. Mapped IPv4 sockets normalize to the IPv4 packet representation.
The full 44-byte key contains native-endian family, protocol 6, zero padding,
16-byte source/destination addresses (IPv4 in the first four bytes, rest zero),
and network-order ports and ACK. See `ebpf/ngx_ebpf.h`.

A retransmitted SYN re-adds the same keys. Extra distinct aliases beyond two,
e.g. from a SYN with another sequence number, are counted and skipped. Another
cookie never replaces a live owner, one whose registration still exists: that
collision marks the key ambiguous, neither owner matches it, and it remains a
tombstone until the LRU map evicts it. A key whose owner is gone is taken over.

PREROUTING processes SYN-ACK packets with RST clear. Every inbound packet reaches
it, so a candidate check comes first: one probe read covers the IP header and the TCP
flags for IPv4 without options and IPv6 without extension headers, and anything
else in those layouts leaves at once; other layouts go to the full parse. It
matches the complete key,
checks registration and ownership, atomically claims the connection,
and publishes headers. Failure to publish releases the claim. Success marks the
connection complete and removes its nonambiguous aliases. The terminal state
prevents recreation after a userspace consume, including retransmitted SYNs.

## Raw bytes and handoff

The versioned private record contains a monotonic timestamp, length, and a
zero-filled 256-byte buffer. Only complete IP/TCP headers are copied. IPv4 options
and up to eight IPv6 hop-by-hop, routing, destination and AH headers are supported
within that bound. Fragments, jumbograms, ESP, malformed or oversized chains,
invalid TCP offsets and inaccessible/nonlinear header bytes are rejected. Original
length/checksum fields are preserved; offload checksum representation is accepted.

“Original” means observed at the early PREROUTING hook. Changes made earlier by
XDP, TC, local OUTPUT, or another namespace cannot be undone. Conventional
DNAT/SNAT is supported; arbitrary TCP sequence rewriting or additional intermediate
address transformations are outside this version.

`ngx_connection_save_synack()` confirms establishment with `TCP_INFO`, then
atomically consumes with `BPF_MAP_LOOKUP_AND_DELETE_ELEM`. It validates the record
version, timestamp and length, and only then allocates exactly `length` bytes of
connection-pool storage to publish `c->saved_synack`. A confirmed miss is processed
once; allocation failure drops the already-consumed record. Errors never fail
upstream traffic.

HTTP calls the helper at connect (covering keepalive reuse), after the connect
test before TLS and before sending the request, and when moving to the next
upstream or finalizing. Each enabled attempt immediately copies available bytes to its
request pool, including on keepalive reuse. Thus log-phase evaluation survives upstream close or pool return.
A retry starts a distinct empty snapshot. Close removes the registration; owned
aliases and an unconsumed capture are removed only when the capture did not
complete or was not consumed, so a normal connection costs one map operation.

## Variables

`$upstream_ja4ts` returns a `window_options_mss_window-scale` string. JA4TS has
no hashed form, so there is no `_string` variant. It shares the raw parser and
formatter with JA4T, retaining option ordering, missing-field, MSS padding and zero-scale
rules. TLS and completion of a TLS handshake are not prerequisites.

The variable is non-cacheable at the Nginx variable layer. An early empty read
does not suppress a later value. It reads only the final upstream attempt, unlike
the per-attempt lists of `$upstream_addr` and `$upstream_status`; an
uncaptured final attempt never falls back to an earlier successful fingerprint.
No upstream, disabled capture, refused connections, Unix sockets and missing
records yield empty values. Response headers and access logging are supported.

## Resources and lifetime

| Map | Key | Capacity |
| --- | --- | ---: |
| `synack_conn` | cookie | 65,536 |
| `synack_expect` | full tuple + ACK | 131,072 |
| `synack_capture` | cookie | 65,536 |
| `synack_stats` | counter ID | fixed |
| `synack_scratch` | zero, per CPU | 1 |

All retention maps are LRU hashes. Scratch storage is transient. Kernel and
userspace failures have diagnostic counters in a shared
mmapable statistics array; updates use atomic additions. Counter IDs are private
and defined in the ABI header. There is no production debug variable or CLI.

Nothing carries a time, and the programs never read the clock: an entry lives
as long as its socket's registration. Capture, consumption and close remove
entries on the fast path, and headers are consumed right after the handshake.
Nothing sweeps: what a failure leaves
behind (a crashed worker, a missed SYN-ACK, an ambiguous key) is never looked up
again, so the LRU maps evict it first when an insert needs room, with bounded
work per insert and no periodic pass in the kernel or a worker. An expectation
whose owner is gone is taken over by the next owner of its key rather than
treated as a collision. The cost is that an insert never fails for room: past capacity, the
oldest live entry is evicted. The consumer counts that as `EVICTED` when both
its registration and its capture are gone. It counts `MISSED` when the
registration is still pending, i.e. the SYN-ACK was not captured. The insert and
collision counters explain some misses; unexplained ones mean traffic took a
path the programs cannot see, or a bug.

Ownership lives outside cycle pools. No enabled configuration means no maps or
attachments. `nginx -t` and signal-only invocations do not touch BPF. Explicitly
enabled capture that cannot initialize fails startup. The master needs sufficient
BPF, Netfilter and probe-read privileges (root on the tested hosts); workers
inherit descriptors and require no BPF administration capabilities.

Graceful reload reuses maps and links. Existing connections retain their policy;
new ones use the new configuration. An entirely disabled running instance must
restart to enable capture: configuration validation rejects such a reload without
terminating the master. Disabling all contexts retains infrastructure until final
shutdown. Sizes, priorities and retention constants require rebuild/restart.
Worker exit closes references without explicitly detaching shared links. Final
closure releases resources. Live binary-upgrade resource handover is deferred.

## Verification and delivery

The first milestone passed on Linux 6.4.0-060400 and Linux 6.8.0-139 using the same
CO-RE proof object. It verified cookie access, tuple normalization, verifier bounds,
loopback ordering, IPv4/IPv6, mapped IPv4, separate-namespace NAT, same-namespace NAT,
untracked traffic and early header preservation. The production collector also
passed lower-level checks on both kernels. The 6.4 run used an isolated QEMU guest;
no host kernel replacement was needed. That proof object and its runner have since
been retired: its loopback cases are covered end to end by `ja4ts-network.t`, and
its separate-namespace and mapped-socket cases by `capture.py` against the
production object.

The acceptance runners are in `test/ebpf/`:

- `capture.py`: production collector, 30 cases (TAP, run with `prove`): malformed packets,
  options/extensions, SYN-data ACK misses, retransmissions, terminal state,
  ambiguous ownership, ACK wraparound, eviction from full maps, stale-owner
  takeover, and
  separate-namespace IPv4/IPv6/mapped/NAT/untracked peers. It is also the
  cross-kernel CO-RE check.
- `nginx.py`: instrumented Nginx, immediate consumption before response variables,
  resources after a failed unprivileged startup, allocation failure, eviction from
  a full registration map, the eviction and miss counters, worker capability drop and
  replacement, reload and shutdown.
- `build-matrix.sh`: production HTTP, HTTP plus stream, and disabled builds.
- `test/ja4ts-config.t`: non-root directive parsing (including `stream {}`), the
  build without the addon, and the clear failure of an unprivileged enabled
  start; run against builds with and without the addon.
- `test/ja4ts-variables.t`: 144 assertions including inheritance, TLS (also a
  failed upstream handshake),
  dynamic peers, retries, log phase, early evaluation, original headers,
  keepalive policy sharing in both orders, and `error_page` into a disabled
  location.
- `test/ja4ts-network.t`: 61 assertions for IPv6, DNAT/SNAT/REDIRECT, later
  PREROUTING rewrites and untracked traffic.
- `test/lib/Ja4tsCapture.pm`: the shared namespace and nftables fixture.

All privileged fixtures use anonymous private network namespaces and owned tables.
NAT chains exist only for NAT cases. `ja4ts-network.t` provisions a deterministic
dummy route for its non-local DNAT case.
Test-only `NGX_SYNACK_TEST=1` instrumentation inspects raw storage and consumes,
and enables allocation-failure injection; it does not exist in production builds.
The `.github/workflows/test-ebpf.yaml` workflow runs on changes to the addon,
patches, module sources or these tests. It checks the committed skeleton,
builds the instrumented nginx once, runs the privileged suites as root and
`ja4ts-config.t` as a normal user, rejects skips, and builds all three
production variants in parallel. Existing JA4T regression assertions remain
part of CI. See the fixture README for commands.

Deferred scope: TCP Fast Open on upstream connections, retransmission timing/RST
suffixes, stream capture, and non-linear skb
headers. Capture is optional metadata and individual losses leave
normal proxy behavior unchanged.

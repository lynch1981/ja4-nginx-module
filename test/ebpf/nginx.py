#!/usr/bin/env python3
"""Privileged Nginx lifetime checks; build with NGX_SYNACK_TEST=1.

The production build has no instrumentation or failure-injection environment
variables. This runner fails when instrumentation or privileges are missing.
"""
import ctypes as C
import errno
import json
import os
from pathlib import Path
import queue
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from capture import Connection, Record
from fixture import Stop, Tap, command, namespace


def wait(check, timeout=8):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        time.sleep(0.025)
    raise AssertionError("condition did not become true before timeout")


def resources(kind="map"):
    rows = json.loads(command(os.environ.get("BPFTOOL", "bpftool"), "-j", kind, "show"))
    return {row["id"]: row for row in rows}


class Maps:
    def __init__(self, rows):
        self.lib = C.CDLL("libbpf.so.1", use_errno=True)
        for name, args in {
            "bpf_map_get_fd_by_id": [C.c_uint32],
            "bpf_map_update_elem": [C.c_int, C.c_void_p, C.c_void_p, C.c_uint64],
            "bpf_map_lookup_elem": [C.c_int, C.c_void_p, C.c_void_p],
            "bpf_map_get_next_key": [C.c_int, C.c_void_p, C.c_void_p],
            "bpf_map_delete_elem": [C.c_int, C.c_void_p],
        }.items():
            fn = getattr(self.lib, name)
            fn.restype, fn.argtypes = C.c_int, args
        self.rows = {r["name"].removeprefix("synack_"): r for r in rows.values()}
        self.fds = {name: self.lib.bpf_map_get_fd_by_id(row["id"])
                    for name, row in self.rows.items()}
        assert all(fd >= 0 for fd in self.fds.values())

    def close(self):
        for fd in self.fds.values():
            os.close(fd)
        self.fds.clear()

    def put(self, name, cookie, value):
        k = C.c_uint64(cookie)
        assert self.lib.bpf_map_update_elem(self.fds[name], C.byref(k), C.byref(value), 0) == 0

    def get(self, name, cookie, cls):
        k, value = (C.c_uint32(cookie) if name == "stats" else C.c_uint64(cookie)), cls()
        if self.lib.bpf_map_lookup_elem(self.fds[name], C.byref(k), C.byref(value)):
            assert C.get_errno() == errno.ENOENT
            return None
        return value

    def delete(self, name, cookie):
        k = C.c_uint64(cookie)
        rc = self.lib.bpf_map_delete_elem(self.fds[name], C.byref(k))
        assert rc == 0 or C.get_errno() == errno.ENOENT

    def empty(self, name):
        k = (C.c_ubyte * self.rows[name]["bytes_key"])()
        rc = self.lib.bpf_map_get_next_key(self.fds[name], None, C.byref(k))
        if rc:
            assert C.get_errno() == errno.ENOENT
        return rc != 0


class Backend:
    def __init__(self, *, hold=False):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 23456))
        self.socket.listen(16)
        self.socket.settimeout(0.2)
        self.ready = queue.Queue()
        self.release = threading.Event()
        if not hold:
            self.release.set()
        self.stop = threading.Event()
        self.errors = []
        self.threads = [threading.Thread(target=self.accept, daemon=True)]
        for t in self.threads:
            t.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self.serve, args=(client,), daemon=True)
            self.threads.append(t)
            t.start()

    def serve(self, client):
        try:
            client.settimeout(8)
            with client:
                data = b""
                while b"\r\n\r\n" not in data:
                    block = client.recv(4096)
                    if not block:
                        return
                    data += block
                self.ready.put("request")
                assert self.release.wait(8)
                client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
        except Exception as e:
            self.errors.append(e)

    def close(self):
        self.stop.set()
        self.release.set()
        self.socket.close()
        for t in self.threads:
            t.join(timeout=2)
        assert not self.errors, self.errors


class Nginx:
    def __init__(self, binary, enabled=None, *, env=None):
        self.binary = binary
        self.temp = tempfile.TemporaryDirectory(prefix="synack-nginx-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        (self.root/"logs").mkdir()
        self.path = self.root/"nginx.conf"
        self.log = self.root/"error.log"
        self.env = env or {}
        self.enabled = enabled
        self.proc, self.maps = None, None
        self.before_maps, self.before_links = resources(), resources("link")
        self.write(enabled)

    def write(self, enabled):
        self.enabled = enabled
        policy = "" if enabled is None else f"tcp_save_synack {'on' if enabled else 'off'};"
        self.path.write_text(f'''
daemon off;
master_process on;
user nobody nogroup;
worker_processes 1;
env NGX_SYNACK_TEST_ALLOC_FAIL;
pid {self.root}/nginx.pid;
error_log {self.log} notice;
events {{ worker_connections 128; }}
http {{
    access_log off;
    {policy}
    server {{ listen 127.0.0.1:18080;
        location /ready {{ return 200 "ready"; }}
        location /on {{ proxy_pass http://127.0.0.1:23456;
            add_header X-FP "[$upstream_ja4ts]" always; }}
        location /off {{ tcp_save_synack off; proxy_pass http://127.0.0.1:23456;
            add_header X-FP "[$upstream_ja4ts]" always; }}
        location /abort {{ proxy_pass http://192.0.2.2:23456; proxy_connect_timeout 2s; }}
    }}
}}
''')

    def start(self):
        self.stderr = (self.root/"stderr").open("wb")
        self.proc = subprocess.Popen([self.binary, "-p", str(self.root), "-c", str(self.path)],
                                     env={**os.environ, **self.env}, stdout=self.stderr, stderr=self.stderr)
        def ready():
            if self.proc.poll() is not None:
                raise AssertionError((self.log.read_text() if self.log.exists() else "")
                                     + (self.root/"stderr").read_text())
            try:
                return b"200 OK" in self.request("/ready")
            except OSError:
                return False
        wait(ready)
        rows = {i: r for i, r in resources().items() if i not in self.before_maps}
        if self.enabled:
            assert {r["name"] for r in rows.values()} == {
                "synack_conn", "synack_expect", "synack_capture", "synack_stats", "synack_scratch"}, (rows, self.log.read_text(), (self.root/"stderr").read_text())
            self.maps = Maps(rows)
            assert self.maps.rows["conn"]["max_entries"] == 65536
            assert self.maps.rows["capture"]["max_entries"] == 65536
            assert self.maps.rows["expect"]["max_entries"] == 131072
        else:
            assert not rows
        self.map_ids = set(rows)
        self.link_ids = set(resources("link")) - set(self.before_links)
        assert len(self.link_ids) == (4 if self.enabled else 0)

    def worker(self):
        children = Path(f"/proc/{self.proc.pid}/task/{self.proc.pid}/children").read_text().split()
        return int(children[-1]) if children else None

    def begin(self, path="/on", port=18080):
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.sendall(f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
        return client

    @staticmethod
    def finish(client):
        data = b""
        with client:
            while True:
                block = client.recv(65536)
                if not block:
                    return data
                data += block

    def request(self, path="/on", port=18080):
        return self.finish(self.begin(path, port))

    def handoffs(self):
        return re.findall(r"synack test handoff: cookie=(\d+) len=(\d+) kernel=(\d+) aliases=(\d+) raw=([0-9a-f]+)", self.log.read_text())

    def reload(self, enabled):
        old = self.worker()
        self.write(enabled)
        self.proc.send_signal(signal.SIGHUP)
        wait(lambda: self.worker() and self.worker() != old
             and not Path(f"/proc/{old}").exists())
        assert self.map_ids <= set(resources())
        assert self.link_ids <= set(resources("link"))

    def close(self):
        if self.proc:
            self.proc.send_signal(signal.SIGQUIT)
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                raise AssertionError("Nginx did not shut down gracefully")
            self.stderr.close()
        if self.maps:
            self.maps.close()
        if hasattr(self, "map_ids"):
            wait(lambda: not self.map_ids.intersection(resources()))
            wait(lambda: not self.link_ids.intersection(resources("link")))
        self.temp.cleanup()


def check_bpftool():
    """resources() lists maps and links with bpftool; say so clearly instead
    of failing every test with FileNotFoundError."""
    tool = os.environ.get("BPFTOOL", "bpftool")
    try:
        ok = subprocess.run([tool, "version"], capture_output=True).returncode == 0
    except OSError:
        ok = False
    if not ok:
        Tap.bail(f"nginx.py needs a working bpftool ({tool!r} failed); install it or "
                 "set BPFTOOL, e.g. to /usr/lib/linux-tools/<version>/bpftool")


def check_build(binary):
    """Check `nginx -V` up front so a wrong build fails with a clear reason
    instead of a timeout."""
    out = subprocess.run([binary, "-V"], capture_output=True, text=True).stderr
    missing = [what for what, pattern in [
        ("the ebpf addon (--add-module=.../ebpf)", r"--add-module=\S*/ebpf\b"),
        ("the test instrumentation (--with-cc-opt=-DNGX_SYNACK_TEST=1)", r"-DNGX_SYNACK_TEST=1\b"),
    ] if not re.search(pattern, out)]
    if missing:
        Tap.bail(f"{binary} lacks " + "; ".join(missing)
                 + ". Build a separate instrumented nginx; see test/ebpf/README.md.")


def test_default(binary, tap):
    with tap.case("default-off, configuration test, signal-only, restart requirement"):
        n = Nginx(binary)
        try:
            n.start()
            n.write(True)
            # Configuration tests must parse the enabled policy without loading BPF.
            command(binary, "-t", "-p", str(n.root), "-c", str(n.path))
            assert set(resources()) == set(n.before_maps)
            n.proc.send_signal(signal.SIGHUP)
            wait(lambda: "enabling capture requires a restart" in n.log.read_text())
            assert n.proc.poll() is None, "failed reload terminated the master"
            assert b"200 OK" in n.request("/ready")
            assert set(resources()) == set(n.before_maps)
            # Signal-only parse of an enabled configuration must not create maps.
            command(binary, "-s", "reopen", "-p", str(n.root), "-c", str(n.path))
            assert set(resources()) == set(n.before_maps)
        finally:
            n.close()


def test_startup_failure(binary, tap):
    with tap.case("enabled startup without capture privileges fails and leaks nothing"):
        n = Nginx(binary, True)
        try:
            n.root.chmod(0o777)
            (n.root/"logs").chmod(0o777)
            result = subprocess.run([binary, "-p", str(n.root), "-c", str(n.path)],
                                    user="nobody", group="nogroup", capture_output=True, timeout=8)
            assert result.returncode != 0
            assert b"cannot load the BPF capture programs" in result.stderr
            # libbpf detail goes to the error log at notice, not raw to stderr
            assert b"libbpf:" not in result.stderr
            assert set(resources()) == set(n.before_maps)
            assert set(resources("link")) == set(n.before_links)
        finally:
            n.close()


def test_http(binary, tap):
    # The phases share one nginx and build on each other, so a failure stops
    # the rest; the shutdown check still runs.
    backend, n = Backend(hold=True), Nginx(binary, True)
    client = None
    try:
        with tap.case("immediate consume before response variables, request snapshot, "
                      "unprivileged worker", stop=True):
            n.start()
            worker = n.worker()
            status = Path(f"/proc/{worker}/status").read_text()
            assert re.search(r"CapEff:\s+0+\n", status), "worker retains administration capabilities"
            client = n.begin()
            assert backend.ready.get(timeout=5) == "request"
            handoff = wait(lambda: n.handoffs())[-1]
            cookie, length, present, _, raw = handoff
            assert present == "0" and len(bytes.fromhex(raw)) == int(length)
            assert n.maps.empty("capture") and n.maps.empty("expect")
            assert n.maps.get("conn", int(cookie), Connection).phase == 2
            backend.release.set()
            response = n.finish(client)
            client = None
            assert b"200 OK" in response and re.search(rb"X-FP: \[\d+_", response)
            wait(lambda: n.maps.empty("conn"))
            assert b"X-FP: []" in n.request("/off")
            assert len(n.handoffs()) == 1

        with tap.case("worker replacement, shared links, sweep lease takeover", stop=True):
            # Kill the lease holder and verify the replacement sweeps expired state.
            fake = (1 << 62)
            # Observe the original worker sweep first, so it owns a live lease.
            n.maps.put("conn", fake-1, Connection(deadline=time.monotonic_ns()-1))
            n.maps.put("capture", fake-2, Record(version=1, length=40,
                                                timestamp=time.monotonic_ns()-11_000_000_000))
            wait(lambda: n.maps.get("conn", fake-1, Connection) is None)
            wait(lambda: n.maps.get("capture", fake-2, Record) is None)
            n.maps.put("conn", fake, Connection(deadline=time.monotonic_ns()-1))
            n.maps.put("capture", fake, Record(version=1, length=40,
                                              timestamp=time.monotonic_ns()-11_000_000_000))
            old = n.worker()
            os.kill(old, signal.SIGKILL)
            wait(lambda: n.worker() and n.worker() != old)
            wait(lambda: n.maps.get("conn", fake, Connection) is None, timeout=7)
            assert n.maps.get("capture", fake, Record) is None
            assert re.search(rb"X-FP: \[\d+_", n.request())

        with tap.case("reload reuses maps and changes policy for new sockets", stop=True):
            n.reload(False)
            assert b"X-FP: []" in n.request()
            n.reload(True)
            assert re.search(rb"X-FP: \[\d+_", n.request())

        with tap.case("registration exhaustion preserves proxy traffic", stop=True):
            wait(lambda: n.maps.empty("conn"))
            state = Connection(deadline=time.monotonic_ns()+120_000_000_000)
            start = 1 << 61
            count = n.maps.rows["conn"]["max_entries"]
            try:
                for i in range(count):
                    n.maps.put("conn", start+i, state)
                response = n.request()
                assert b"200 OK" in response and b"X-FP: []" in response
                assert "registration failed, metadata unavailable" in n.log.read_text()
                assert n.maps.get("stats", 6, C.c_uint64).value == 1
            finally:
                for i in range(count):
                    n.maps.delete("conn", start+i)

        with tap.case("aborted connect cleanup", stop=True):
            command("ip", "link", "add", "abort0", "type", "dummy")
            command("ip", "addr", "add", "192.0.2.1/24", "dev", "abort0")
            command("ip", "link", "set", "abort0", "up")
            client = n.begin("/abort")
            wait(lambda: not n.maps.empty("conn"))
            client.close()
            client = None
            wait(lambda: n.maps.empty("conn"))
            assert n.maps.empty("capture")
    except Stop:
        tap.note("remaining test_http phases skipped after the failure above")
    finally:
        if client:
            client.close()
        backend.release.set()
        with tap.case("final shutdown releases all maps and links"):
            n.close()
            backend.close()


def test_allocation(binary, tap):
    with tap.case("allocation failure discards capture and preserves traffic"):
        backend = Backend()
        n = Nginx(binary, True, env={"NGX_SYNACK_TEST_ALLOC_FAIL": "1"})
        try:
            n.start()
            response = n.request()
            assert b"200 OK" in response and b"X-FP: []" in response
            assert not n.handoffs()
            assert n.maps.get("stats", 7, C.c_uint64).value == 1
            wait(lambda: n.maps.empty("capture") and n.maps.empty("conn"))
        finally:
            n.close()
            backend.close()


def main():
    if len(sys.argv) != 2:
        Tap.bail("usage: sudo python3 test/ebpf/nginx.py /path/to/instrumented/nginx")
    if os.geteuid():
        Tap.bail("nginx.py must run as root")
    binary = os.path.abspath(sys.argv[1])
    check_bpftool()
    check_build(binary)
    try:
        namespace()
    except Exception as e:
        Tap.bail(f"cannot enter a private network namespace: {e}")
    tap = Tap()
    for test in (test_default, test_startup_failure, test_http, test_allocation):
        try:
            test(binary, tap)
        except Exception:
            # Setup outside any case, e.g. the backend port was taken.
            with tap.case(f"{test.__name__} setup"):
                raise
    sys.exit(tap.done())


if __name__ == "__main__":
    main()

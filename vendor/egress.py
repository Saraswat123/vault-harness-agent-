"""Egress allowlist for Python agents: which hosts this process may talk to. Stdlib only.

    policy = EgressPolicy(["api.groq.com", "*.openrouter.ai", "api.github.com:443"])
    policy.install()                      # process-wide until uninstall()

Enforced at the socket layer, so requests, httpx, urllib and asyncio are all covered (not only code that calls a helper):
  * name lookups (socket.getaddrinfo) for a host that is not allowed raise EgressDenied before any packet is sent
  * a name that resolves to a private / link-local / metadata address is refused (DNS-rebinding and SSRF), unless allow_private
  * a direct connect() to an IP is allowed only if that IP came from an allowed lookup, or is loopback (allow_loopback)

Patterns: "host", "*.suffix" (subdomains only, not the apex), "host:443" (port-restricted). None = no policy; [] = deny everything.

Limits, stated plainly: it covers this Python process only. A subprocess (for example email_sender.py), a native extension that opens
its own sockets without the Python socket module, and anything that already holds an open connection are NOT covered. It restricts WHERE
data can go; it does not inspect WHAT is sent.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
from typing import Callable, Iterable, Optional


class EgressDenied(RuntimeError):
    pass


def _ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


class EgressPolicy:
    def __init__(self, allow: Iterable[str], allow_loopback: bool = True, allow_private: bool = False,
                 on_event: Optional[Callable[[str, str, Optional[int]], None]] = None, error_cls=EgressDenied):
        self.rules = []                                        # (host pattern, port or None)
        for a in allow:
            h, _, p = str(a).strip().lower().rpartition(":") if str(a).count(":") == 1 else (str(a).strip().lower(), "", "")
            self.rules.append((h or str(a).strip().lower(), int(p) if p.isdigit() else None))
        self.allow_loopback, self.allow_private = allow_loopback, allow_private
        self.on_event, self.error_cls = on_event, error_cls
        self._ok_ips: set = set()
        self._seen: set = set()
        self._lock = threading.Lock()
        self._orig = None

    # ---- decisions ---------------------------------------------------------
    def _emit(self, kind, host, port):
        if not self.on_event:
            return
        if kind == "allowed":
            with self._lock:
                if host in self._seen:
                    return
                self._seen.add(host)
        self.on_event(kind, host, port)

    def _deny(self, host, port, why):
        self._emit("denied", host, port)
        raise self.error_cls(f"egress denied: {host}{':' + str(port) if port else ''} ({why})")

    def _name_allowed(self, host: str, port) -> bool:
        for pat, pport in self.rules:
            if pport is not None and port is not None and int(port) != pport:
                continue
            if pat == host or (pat.startswith("*.") and host.endswith(pat[1:]) and host != pat[2:]):
                return True
        return False

    def check_name(self, host: str, port=None, emit: bool = True) -> None:
        h = (host or "").strip().lower().strip("[]")
        if h in ("", "0.0.0.0", "::"):                         # bind / wildcard: not egress
            return
        ip = _ip(h)
        if h == "localhost" or (ip and ip.is_loopback):
            if self.allow_loopback or self._name_allowed(h, port):
                return
            self._deny(h, port, "loopback not allowed")
        if ip is not None:                                     # an IP literal must be listed explicitly
            if self._name_allowed(h, port):
                return
            self._deny(h, port, "IP literal not on the allowlist")
        if not self._name_allowed(h, port):
            self._deny(h, port, "host not on the allowlist")
        if emit:
            self._emit("allowed", h, port)

    # ---- install / uninstall -----------------------------------------------
    def install(self):
        if self._orig is not None:
            return self.uninstall
        real_gai, real_connect, real_connect_ex = socket.getaddrinfo, socket.socket.connect, socket.socket.connect_ex
        self._orig = (real_gai, real_connect, real_connect_ex)
        pol = self

        def gai(host, port, *a, **k):
            if isinstance(host, bytes):
                host = host.decode("idna", "ignore")
            if host is None:
                return real_gai(host, port, *a, **k)
            pol.check_name(str(host), port if isinstance(port, int) else None, emit=False)
            res = real_gai(host, port, *a, **k)
            keep = []
            for r in res:
                ip = _ip(r[4][0])
                if ip is not None and not ip.is_loopback and (ip.is_private or ip.is_link_local or ip.is_reserved) and not pol.allow_private:
                    continue
                keep.append(r)
                with pol._lock:
                    pol._ok_ips.add(r[4][0])
            if res and not keep:
                pol._deny(str(host), port if isinstance(port, int) else None, "resolves to a private or link-local address")
            if _ip(str(host)) is None and str(host).lower() not in ("localhost",):
                pol._emit("allowed", str(host).lower(), port if isinstance(port, int) else None)
            return keep

        def gate(self_sock, address):
            if isinstance(address, tuple) and address and isinstance(address[0], str) and self_sock.family in (socket.AF_INET, socket.AF_INET6):
                ip = _ip(address[0])
                if ip is not None and not ip.is_loopback and address[0] not in pol._ok_ips and not pol._name_allowed(address[0], address[1] if len(address) > 1 else None):
                    pol._deny(address[0], address[1] if len(address) > 1 else None, "direct connect to an IP that no allowed lookup returned")
                if ip is not None and ip.is_loopback and not pol.allow_loopback:
                    pol._deny(address[0], address[1] if len(address) > 1 else None, "loopback not allowed")

        def connect(self_sock, address):
            gate(self_sock, address)
            return real_connect(self_sock, address)

        def connect_ex(self_sock, address):
            gate(self_sock, address)
            return real_connect_ex(self_sock, address)

        socket.getaddrinfo, socket.socket.connect, socket.socket.connect_ex = gai, connect, connect_ex
        return self.uninstall

    def uninstall(self):
        if self._orig is not None:
            socket.getaddrinfo, socket.socket.connect, socket.socket.connect_ex = self._orig
            self._orig = None

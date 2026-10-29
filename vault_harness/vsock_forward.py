"""Byte forwarder used for the enclave's only way out. The enclave has no network: a local port inside it is piped to the parent over vsock,
and the parent runs `vsock-proxy` to api.stripe.com:443. TLS stays end to end between the enclave and Stripe, so the parent sees only
encrypted bytes. `tcp://` targets exist so the forwarder can be tested without AWS."""
import socket
import threading

from vault_harness.enclave_rpc import _dial


def _pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def forward(listen_host: str, listen_port: int, target_url: str) -> socket.socket:
    """Listen locally; for each connection open `target_url` (tcp://h:p or vsock://cid:p) and pipe both ways. Returns the listener."""
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind((listen_host, listen_port)); ls.listen(32)

    def loop():
        while True:
            try:
                c, _ = ls.accept()
            except OSError:
                return
            try:
                up = _dial(target_url, 30)
            except OSError:
                c.close(); continue
            threading.Thread(target=_pipe, args=(c, up), daemon=True).start()
            threading.Thread(target=_pipe, args=(up, c), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return ls

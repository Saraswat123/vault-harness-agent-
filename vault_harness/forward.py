"""Processor that runs INSIDE the trust boundary: replays the captured request (with the real card) and returns the raw reply.
Kept in its own module so the enclave image needs only cryptography + httpx."""
import httpx


class ForwardProcessor:
    """Runs inside the trust boundary: replays the captured request (with the real card) and returns the raw reply."""

    def __init__(self, transport: httpx.BaseTransport = None):
        self._http = httpx.Client(timeout=30, transport=transport)

    def __call__(self, req: dict) -> dict:
        keep = {"content-type", "accept", "accept-language", "user-agent"}
        h = {k: v for k, v in (req.get("headers") or {}).items() if k.lower() in keep}
        r = self._http.request(req.get("method", "POST"), req["url"], content=req["body"], headers=h)
        return {"status": r.status_code, "raw": r.text, "ctype": r.headers.get("content-type", "application/json")}

"""The only code in unopened that opens network connections (rule 3).

It is imported only when the user passes --reputation, and it only ever sends what
the callers in this package build: a hash and an API key. A test checks that no other
module imports networking code and that triage without --reputation never imports
this one.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request

MAX_RESPONSE = 2 * 1024 * 1024
USER_AGENT = "unopened-triage (hash lookup only)"


class TransportError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind  # "timeout" or "network"


def request(method: str, url: str, headers: dict[str, str], body: bytes | None,
            timeout: float) -> tuple[int, bytes]:
    """Perform one HTTPS request with certificate verification. Returns (status, body)."""
    if not url.startswith("https://"):
        raise TransportError("network", "refusing a non-HTTPS URL")
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": USER_AGENT, **headers})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return resp.status, resp.read(MAX_RESPONSE)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE)
    except TimeoutError as exc:
        raise TransportError("timeout", f"no answer within {timeout:g} seconds") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError | socket.timeout):
            raise TransportError("timeout", f"no answer within {timeout:g} seconds") from exc
        raise TransportError("network", str(exc.reason)) from exc
    except OSError as exc:
        raise TransportError("network", str(exc)) from exc

"""Constrained Docker Engine read operations over a Unix socket."""
from __future__ import annotations

import http.client
import json
import re
import socket
import time
from urllib.parse import parse_qsl, urlsplit

from .observer import CONTAINER_ID_RE, PROJECT_RE, project_of

API_PREFIX = "/v1.41"
MAX_CONTAINERS = 200
MAX_JSON_BYTES = 1024 * 1024
MAX_LOG_BYTES = 65536


class ObservationFailed(Exception):
    """No internal Docker payload, URL, credential or exception escapes to a caller."""


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


def _allowed_engine_route(route: str) -> bool:
    """Defense in depth: reject all methods/routes outside three exact GET families."""
    if len(route) > 256 or any(x in route for x in ("%", "\\", "//", "#")):
        return False
    p = urlsplit(route)
    if p.scheme or p.netloc or p.fragment:
        return False
    if p.path == API_PREFIX + "/containers/json":
        return p.query == "all=1"
    match = re.fullmatch(re.escape(API_PREFIX) + r"/containers/([0-9a-f]{64})/(json|logs)", p.path)
    if not match:
        return False
    if match.group(2) == "json":
        return p.query == ""
    query = parse_qsl(p.query, keep_blank_values=True, strict_parsing=True)
    if len(query) != 6 or len({k for k, _ in query}) != 6:
        return False
    args = dict(query)
    if set(args) != {"stdout", "stderr", "timestamps", "follow", "since", "tail"}:
        return False
    if any(args[k] != v for k, v in (("stdout", "1"), ("stderr", "1"), ("timestamps", "0"), ("follow", "0"))):
        return False
    return args["since"].isdigit() and args["tail"].isdigit() and 1 <= int(args["tail"]) <= 100


class DockerUnixTransport:
    """Only exact GET routes; cannot forward arbitrary Docker API requests."""
    def __init__(self, socket_path: str, timeout: float = 3.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def get(self, route: str, max_bytes: int) -> bytes:
        if not _allowed_engine_route(route) or max_bytes not in (MAX_JSON_BYTES, MAX_LOG_BYTES):
            raise ObservationFailed("denied Docker request")
        connection = _UnixHTTPConnection(self.socket_path, self.timeout)
        try:
            connection.request("GET", route, headers={"Accept": "application/json", "Connection": "close"})
            response = connection.getresponse()
            # No redirects; do not follow Docker/remote-supplied locations.
            if response.status != 200:
                raise ObservationFailed("Docker observation unavailable")
            content = response.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise ObservationFailed("Docker response exceeds limit")
            return content
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise ObservationFailed("Docker observation unavailable") from exc
        finally:
            connection.close()


def _json_object(data: bytes, expected_type: type):
    try:
        value = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise ObservationFailed("malformed Docker response") from exc
    if not isinstance(value, expected_type):
        raise ObservationFailed("unexpected Docker response type")
    return value


def _decode_logs(payload: bytes, tty: bool) -> list[str]:
    if tty:
        return payload.decode("utf-8", errors="replace").splitlines()
    fragments: list[bytes] = []
    at = 0
    while at < len(payload):
        if at + 8 > len(payload):
            raise ObservationFailed("incomplete Docker log frame")
        header = payload[at:at + 8]
        if header[0] not in (1, 2) or header[1:4] != b"\x00\x00\x00":
            raise ObservationFailed("invalid Docker log frame")
        n = int.from_bytes(header[4:8], "big")
        at += 8
        if n > MAX_LOG_BYTES or at + n > len(payload):
            raise ObservationFailed("invalid Docker log length")
        fragments.append(payload[at:at + n])
        at += n
    return b"".join(fragments).decode("utf-8", errors="replace").splitlines()


class DockerGatewayProvider:
    """Trusted reader used behind the unprivileged API, never exposed directly.

    Project membership is revalidated against fresh inspect data for every log
    retrieval, and the operator's verified-project allowlist is applied here
    independently of any upstream API permission checks.
    """
    source = "docker-api"

    def __init__(self, transport, verified_log_projects: frozenset[str], clock=time.time):
        if not isinstance(verified_log_projects, frozenset) or not all(
            isinstance(p, str) and PROJECT_RE.fullmatch(p) for p in verified_log_projects
        ):
            raise ValueError("invalid project policy")
        self.transport = transport
        self.verified_log_projects = verified_log_projects
        self.clock = clock

    def _inspect(self, exact_id: str) -> dict:
        if not isinstance(exact_id, str) or not CONTAINER_ID_RE.fullmatch(exact_id):
            raise ObservationFailed("invalid container identity")
        raw = _json_object(self.transport.get(f"{API_PREFIX}/containers/{exact_id}/json", MAX_JSON_BYTES), dict)
        if raw.get("Id") != exact_id:
            raise ObservationFailed("Docker inspect identity mismatch")
        return raw

    def list_containers(self) -> list[dict]:
        listing = _json_object(self.transport.get(API_PREFIX + "/containers/json?all=1", MAX_JSON_BYTES), list)
        if len(listing) > MAX_CONTAINERS:
            raise ObservationFailed("container count exceeded")
        ids = [r.get("Id") for r in listing if isinstance(r, dict)]
        if len(ids) != len(listing) or len(set(ids)) != len(ids) or any(
            not isinstance(cid, str) or not CONTAINER_ID_RE.fullmatch(cid) for cid in ids
        ):
            raise ObservationFailed("ambiguous Docker inventory")
        return [self._inspect(cid) for cid in ids]

    def get_logs(self, exact_id: str, since_minutes: int, limit: int) -> list[str]:
        if not isinstance(exact_id, str) or not CONTAINER_ID_RE.fullmatch(exact_id):
            raise ObservationFailed("invalid container identity")
        if not isinstance(since_minutes, int) or not 1 <= since_minutes <= 15 or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ObservationFailed("invalid log bounds")
        inspected = self._inspect(exact_id)
        project = project_of(inspected)
        if not project or project not in self.verified_log_projects:
            raise ObservationFailed("log project not authorized")
        epoch = int(self.clock()) - since_minutes * 60
        route = f"{API_PREFIX}/containers/{exact_id}/logs?stdout=1&stderr=1&timestamps=0&follow=0&since={max(0, epoch)}&tail={limit}"
        payload = self.transport.get(route, MAX_LOG_BYTES)
        config = inspected.get("Config", {})
        tty = isinstance(config, dict) and config.get("Tty") is True
        return _decode_logs(payload, tty)[-limit:]

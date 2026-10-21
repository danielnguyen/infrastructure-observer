"""Bounded HTTP endpoints for container inventory and diagnostics."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from urllib.parse import urlsplit, parse_qsl

HOST_ALLOWLIST = {"example-host-a": frozenset({"approved-project"}), "example-host-b": frozenset()}
PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
CONTAINER_ID_RE = re.compile(r"^[a-f0-9]{64}$")
REDACT = [
    re.compile(r"(?i)\b(password|passwd|token|api[_-]?key|secret)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+"),
]

class Denied(Exception):
    def __init__(self, code: str, status: int = 403):
        self.code, self.status = code, status

class FixtureProvider:
    """In-memory provider for deterministic testing and local examples."""
    def __init__(self, containers: list[dict], logs: dict[str, list[str]] | None = None):
        self.containers = containers
        self.log_lines = logs or {}

    def list_containers(self) -> list[dict]:
        return list(self.containers)

    def get_logs(self, exact_id: str, since_minutes: int, limit: int) -> list[str]:
        return self.log_lines.get(exact_id, [])[-limit:]


def project_of(record: dict) -> str | None:
    cfg = record.get("Config", {})
    nested = cfg.get("Labels") if isinstance(cfg, dict) else None
    summary = record.get("Labels")
    # A full inspect uses Config.Labels; a list summary uses top-level Labels.
    # Inconsistent labels must not become log authorization evidence.
    nested_project = nested.get("com.docker.compose.project") if isinstance(nested, dict) else None
    summary_project = summary.get("com.docker.compose.project") if isinstance(summary, dict) else None
    if nested_project is not None and summary_project is not None and nested_project != summary_project:
        return None
    value = nested_project if nested_project is not None else summary_project
    return value if isinstance(value, str) and PROJECT_RE.fullmatch(value) else None


def projection(r: dict, extended: bool = False) -> dict:
    """Allowlists fields instead of editing raw Docker inspect JSON."""
    state = r.get("State", {})
    if not isinstance(state, dict):
        state = {}
    cfg = r.get("Config", {})
    if not isinstance(cfg, dict):
        cfg = {}
    ports = r.get("Ports")
    safe_ports = []
    if isinstance(ports, list):
        for p in ports[:32]:
            if isinstance(p, dict):
                safe_ports.append({k: p[k] for k in ("PrivatePort", "PublicPort", "Type") if k in p and isinstance(p[k], (int, str))})
    else:
        network = r.get("NetworkSettings", {})
        ports_map = network.get("Ports", {}) if isinstance(network, dict) else {}
        if isinstance(ports_map, dict):
            for key, bindings in list(sorted(ports_map.items()))[:32]:
                m = re.fullmatch(r"([0-9]{1,5})/(tcp|udp)", key)
                if not m or not 0 < int(m.group(1)) <= 65535:
                    continue
                if not isinstance(bindings, list):
                    continue
                for binding in bindings[:4]:
                    if not isinstance(binding, dict):
                        continue
                    val = binding.get("HostPort")
                    if isinstance(val, str) and val.isdigit() and 0 < int(val) <= 65535:
                        safe_ports.append({"PrivatePort": int(m.group(1)), "PublicPort": int(val), "Type": m.group(2)})
    result = {
        "id": r.get("Id"),
        "name": r.get("Name"),
        "project": project_of(r),
        "image": cfg.get("Image") if isinstance(cfg.get("Image"), str) else None,
        "image_id": r.get("Image") if isinstance(r.get("Image"), str) else None,
        "status": state.get("Status"),
        "health": state.get("Health", {}).get("Status") if isinstance(state.get("Health"), dict) else None,
        "ports": safe_ports,
    }
    if extended:
        result.update({"restart_count": r.get("RestartCount"), "exit_code": state.get("ExitCode"),
                       "started_at": state.get("StartedAt"), "finished_at": state.get("FinishedAt")})
    return result


def redact_line(s: str) -> str:
    value = s[:2048]
    for pat in REDACT:
        value = pat.sub("[REDACTED]", value)
    return value

class Observer:
    def __init__(self, host: str, provider: FixtureProvider):
        if host not in HOST_ALLOWLIST:
            raise ValueError("unknown host")
        self.host = host
        self.provider = provider

    def handle(self, method: str, path: str) -> tuple[int, dict]:
        try:
            return self._handle(method, path)
        except Denied as error:
            return error.status, {"error": error.code, "host": self.host}
        except Exception:
            return 503, {"error": "OBSERVATION_UNAVAILABLE", "host": self.host, "partial": True}

    def _handle(self, method: str, path: str) -> tuple[int, dict]:
        if method != "GET":
            raise Denied("METHOD_DENIED", 405)
        if len(path) > 256 or "%" in path or "\\" in path or "//" in path:
            raise Denied("BAD_PATH", 400)
        u = urlsplit(path)
        if u.scheme or u.netloc or u.fragment or not u.path.startswith("/"):
            raise Denied("BAD_PATH", 400)
        args: dict[str, str] = {}
        for key, value in parse_qsl(u.query, keep_blank_values=True, strict_parsing=True):
            if key in args:
                raise Denied("BAD_QUERY", 400)
            args[key] = value
        if u.path == "/v1/health":
            if args: raise Denied("BAD_QUERY", 400)
            return 200, {"host": self.host, "mode": "offline-fixture", "ready": True}
        containers = self.provider.list_containers()
        if len(containers) > 1000: raise Denied("INVENTORY_LIMIT", 503)
        # Exact, fully qualified IDs. Duplicate IDs cause fail-closed instead of silently selecting one.
        ids = [c.get("Id") for c in containers]
        if any(not isinstance(i, str) or not CONTAINER_ID_RE.fullmatch(i) for i in ids) or len(set(ids)) != len(ids):
            raise Denied("AMBIGUOUS_INVENTORY", 503)
        base = {"host": self.host, "observed_at": datetime.now(timezone.utc).isoformat(),
                "source": getattr(self.provider, "source", "synthetic-fixture"), "partial": False}
        if u.path == "/v1/containers" and not args:
            return 200, {**base, "containers": [projection(c) for c in containers]}
        if u.path == "/v1/projects" and not args:
            projects: dict[str, int] = {}
            for c in containers:
                project = project_of(c) or "unknown"
                projects[project] = projects.get(project, 0) + 1
            return 200, {**base, "projects": [{"name": p, "count": n} for p, n in sorted(projects.items())]}
        match = re.fullmatch(r"/v1/containers/([a-f0-9]{64})", u.path)
        if match and not args:
            found = next((c for c in containers if c["Id"] == match.group(1)), None)
            if not found: raise Denied("NOT_FOUND", 404)
            return 200, {**base, "container": projection(found, extended=True)}
        match = re.fullmatch(r"/v1/projects/([a-z][a-z0-9-]{0,62})/logs", u.path)
        if match:
            name = match.group(1)
            # Authorization precedes any per-container log collection.
            if name not in HOST_ALLOWLIST[self.host]:
                raise Denied("LOG_PROJECT_DENIED")
            if set(args) != {"since_minutes", "limit"}:
                raise Denied("BAD_QUERY", 400)
            if not args["since_minutes"].isdigit() or not args["limit"].isdigit():
                raise Denied("BAD_QUERY", 400)
            since_minutes, limit = int(args["since_minutes"]), int(args["limit"])
            if not 1 <= since_minutes <= 15 or not 1 <= limit <= 100:
                raise Denied("QUERY_LIMIT", 400)
            members = [c for c in containers if project_of(c) == name]
            if not members: raise Denied("PROJECT_NOT_VERIFIED", 403)
            # Global output cap. Real adapter must also enforce backend timeouts/byte budgets.
            output: list[dict] = []
            remaining = min(limit, 100)
            truncated = False
            for c in members:
                if remaining <= 0:
                    truncated = True
                    break
                lines = self.provider.get_logs(c["Id"], since_minutes, remaining)
                if len(lines) > remaining:
                    lines = lines[:remaining]
                    truncated = True
                for line in lines:
                    if not isinstance(line, str):
                        raise Denied("BAD_LOG_RESPONSE", 503)
                    output.append({"container_id": c["Id"], "line": redact_line(line)})
                    remaining -= 1
            return 200, {**base, "project": name, "logs": output, "truncated": truncated,
                         "warning": "Best-effort redaction does not guarantee removal of unknown secrets"}
        raise Denied("NOT_FOUND", 404)


def run_local_fixture_server(observer: Observer, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, method: str):
            code, body = observer.handle(method, self.path)
            raw = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_GET(self): self._reply("GET")
        def do_POST(self): self._reply("POST")
        def do_PUT(self): self._reply("PUT")
        def do_DELETE(self): self._reply("DELETE")
        def log_message(self, *_): pass
    with ThreadingHTTPServer(("127.0.0.1", port), Handler) as server:
        server.serve_forever()

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Serve in-memory container fixtures on loopback.")
    p.add_argument("--offline-fixture", action="store_true", required=True)
    p.add_argument("--host", choices=sorted(HOST_ALLOWLIST), required=True)
    p.add_argument("--port", type=int, default=8765)
    opts = p.parse_args()
    print("Serving in-memory fixtures at 127.0.0.1", flush=True)
    run_local_fixture_server(Observer(opts.host, FixtureProvider([])), opts.port)

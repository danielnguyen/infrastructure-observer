"""Exercise a disposable observer stack through its actual HTTPS listener."""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import time


COMPOSE = ["sudo", "--preserve-env=OBSERVER_IMAGE,OBSERVER_HOST,OBSERVER_LOG_PROJECTS,OBSERVER_BIND_IP,OBSERVER_CREDENTIALS_DIR", "docker", "compose", "-f", "deployment/compose.yaml"]


def inspect(service: str) -> dict:
    cid = subprocess.check_output([*COMPOSE, "ps", "-q", service], text=True).strip()
    if len(cid) != 64:
        raise AssertionError(f"missing {service} container")
    return json.loads(subprocess.check_output(["sudo", "docker", "inspect", cid], text=True))[0]


def request(path: str, *, authorized: bool = True) -> tuple[int, dict]:
    creds = Path(os.environ["OBSERVER_CREDENTIALS_DIR"])
    token = (creds / "token").read_text().strip()
    context = ssl.create_default_context(cafile=str(creds / "cert.pem"))
    connection = http.client.HTTPSConnection("127.0.0.1", 8765, timeout=3, context=context)
    try:
        headers = {"Authorization": "Bearer " + token} if authorized else {}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def main() -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            status, body = request("/v1/health")
            if status == 200:
                break
        except (OSError, ssl.SSLError, json.JSONDecodeError):
            pass
        time.sleep(0.3)
    else:
        raise AssertionError("HTTPS observer did not become ready")
    assert body["ready"] is True
    assert request("/v1/health", authorized=False)[0] == 401
    assert request("/v1/containers")[0] == 200
    assert request("/v1/projects/synthetic-unapproved/logs?since_minutes=5&limit=5")[0] == 403
    reader = inspect("reader")
    api = inspect("api")
    assert reader["HostConfig"]["NetworkMode"] == "none"
    assert reader["HostConfig"]["ReadonlyRootfs"] is True
    assert api["HostConfig"]["ReadonlyRootfs"] is True
    assert api["Config"]["User"] == "65532:65532"
    assert reader["Config"]["User"] == "0:65532"
    assert all(m["Destination"] != "/var/run/docker.sock" for m in api["Mounts"])
    assert reader["HostConfig"]["CapDrop"] == ["ALL"]
    assert api["HostConfig"]["CapDrop"] == ["ALL"]
    print("Container isolation and HTTPS smoke checks passed")


if __name__ == "__main__":
    main()

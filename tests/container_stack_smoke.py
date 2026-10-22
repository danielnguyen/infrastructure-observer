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


def assert_container_boundaries(reader_id: str, api_id: str) -> None:
    api_probe = """
import os, socket, stat
assert os.geteuid() == 65532
assert not os.path.exists('/var/run/docker.sock')
directory = '/run/observer-ipc'
endpoint = directory + '/reader.sock'
assert stat.S_IMODE(os.stat(directory).st_mode) == 0o2750
assert stat.S_IMODE(os.stat(endpoint).st_mode) == 0o660
for operation in (lambda: os.unlink(endpoint), lambda: os.mkdir(directory + '/unauthorized')):
    try:
        operation()
    except OSError:
        pass
    else:
        raise AssertionError('API identity was able to change the shared IPC mount')
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('/var/run/docker.sock')
except OSError:
    pass
else:
    raise AssertionError('API identity could connect to Docker')
finally:
    s.close()
"""
    reader_probe = """
import os, socket
assert os.geteuid() == 0
assert not os.path.exists('/run/observer-credentials')
try:
    fd = os.open('/should-not-be-created', os.O_WRONLY | os.O_CREAT, 0o600)
except OSError:
    pass
else:
    os.close(fd)
    raise AssertionError('reader unexpectedly wrote to its root filesystem')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect(('192.0.2.1', 443))
except OSError:
    pass
else:
    raise AssertionError('reader unexpectedly accessed the external network')
finally:
    s.close()
"""
    for service_id, probe in ((api_id, api_probe), (reader_id, reader_probe)):
        result = subprocess.run(
            ['sudo', 'docker', 'exec', service_id, 'python3', '-c', probe],
            text=True, capture_output=True, timeout=15,
        )
        if result.returncode:
            raise AssertionError(
                f'container security check failed for {service_id}: {result.stderr[-1200:]}'
            )


def assert_reader_recovers_from_crash() -> None:
    # Docker restart policies require successful initialization before a crash.
    time.sleep(11)
    before = inspect('reader')
    cid = before['Id']
    count = before['RestartCount']
    subprocess.run(
        ['sudo', 'docker', 'exec', cid, 'python3', '-c',
         "import os,signal; os.kill(1,signal.SIGKILL)"],
        text=True, capture_output=True, timeout=12, check=False,
    )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            current = inspect('reader')
            if current['Id'] == cid and current['RestartCount'] > count:
                status, body = request('/v1/health')
                if status == 200 and body['gateway_reachable'] is True:
                    return
        except (OSError, subprocess.CalledProcessError, AssertionError, TimeoutError):
            pass
        time.sleep(0.5)
    raise AssertionError('reader did not recover its IPC socket after a process crash')


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
    assert body["gateway_reachable"] is True
    assert body["docker_checked"] is False
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
    assert_container_boundaries(reader["Id"], api["Id"])
    assert_reader_recovers_from_crash()
    print("Container isolation, recovery, and HTTPS smoke checks passed")


if __name__ == "__main__":
    main()

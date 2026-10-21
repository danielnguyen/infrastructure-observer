"""Integration checks against disposable containers on a real Docker Engine."""

from __future__ import annotations

import grp
import http.client
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

from infrastructure_observer.docker_gateway import DockerGatewayProvider, DockerUnixTransport, _allowed_engine_route
from infrastructure_observer.observer import Observer
from infrastructure_observer.service import LocalGatewayServer


ENABLED = os.environ.get("INFRA_OBSERVER_REAL_DOCKER") == "1"
IMAGE = "busybox:1.36.1"
TOKEN = "local-integration-" + "e" * 48


def docker(*args: str) -> str:
    result = subprocess.run(
        ["docker", *args], check=True, text=True, capture_output=True, timeout=30
    )
    return result.stdout.strip()


@unittest.skipUnless(ENABLED, "requires an explicitly enabled disposable Docker Engine")
class RealDockerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("isolation tests require an ephemeral root-capable CI runner")
        if not all(shutil.which(cmd) for cmd in ("docker", "openssl", "runuser")):
            raise RuntimeError("Docker, OpenSSL and runuser must be installed")
        if not stat.S_ISSOCK(os.stat("/var/run/docker.sock").st_mode):
            raise RuntimeError("requires the local Docker Engine Unix socket")
        docker("info", "--format", "{{.ServerVersion}}")
        nobody = pwd.getpwnam("nobody")
        nogroup = grp.getgrnam("nogroup")
        cls.uid, cls.gid = nobody.pw_uid, nogroup.gr_gid
        cls.temp = tempfile.TemporaryDirectory(prefix="observer-ci-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        os.chown(cls.folder, 0, cls.gid)
        cls.folder.chmod(0o2750)
        suffix = uuid.uuid4().hex[:10]
        cls.approved_project = f"observer-approved-{suffix}"
        cls.denied_project = f"observer-denied-{suffix}"
        cls.created = []
        cls.addClassCleanup(cls._remove_containers)

        # The test harness alone creates and removes containers. The observer
        # never receives Docker mutation capabilities or a Docker CLI.
        containers = (
            (cls.approved_project, "approved", 'echo "visible-ready"; echo "token=synthetic-private"; sleep 240'),
            (cls.denied_project, "denied", 'echo "unapproved-private-log"; sleep 240'),
            (cls.approved_project, "stopped", 'echo "stopped-ready"'),
        )
        for project, kind, command in containers:
            cid = docker(
                "run", "-d", "--name", f"observer-ci-{kind}-{suffix}",
                "--label", f"com.docker.compose.project={project}",
                IMAGE, "sh", "-c", command,
            )
            if len(cid) != 64:
                raise RuntimeError("invalid test container ID")
            cls.created.append(cid)
        cls.approved_id, cls.denied_id, cls.stopped_id = cls.created
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if docker("inspect", "--format", "{{.State.Status}}", cls.stopped_id) == "exited":
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("expected a stopped test container")

        socket_path = str(cls.folder / "reader.sock")
        provider = DockerGatewayProvider(
            DockerUnixTransport("/var/run/docker.sock"), frozenset({cls.approved_project})
        )
        cls.gateway = LocalGatewayServer(
            socket_path, Observer("ci-host", provider, frozenset({cls.approved_project}))
        )
        cls.addClassCleanup(cls.gateway.server_close)
        cls.gateway_thread = threading.Thread(target=cls.gateway.serve_forever, daemon=True)
        cls.gateway_thread.start()
        cls.addClassCleanup(cls._stop_gateway)
        socket_info = os.stat(socket_path)
        if socket_info.st_gid != cls.gid or stat.S_IMODE(socket_info.st_mode) != 0o660:
            raise RuntimeError("local socket group or mode does not enforce the expected boundary")

        cert, key, token = (cls.folder / name for name in ("cert.pem", "key.pem", "token"))
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
            check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        token.write_text(TOKEN + "\n")
        for path in (cert, key, token):
            os.chown(path, cls.uid, cls.gid)
            path.chmod(0o600)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            cls.port = port_socket.getsockname()[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        cls.api = subprocess.Popen(
            ["runuser", "-u", "nobody", "--", sys.executable, "-m",
             "infrastructure_observer.service", "api", "--gateway-socket", socket_path,
             "--listen-ip", "127.0.0.1", "--port", str(cls.port),
             "--tls-cert", str(cert), "--tls-key", str(key), "--token-file", str(token)],
            cwd=str(Path(__file__).resolve().parents[1]), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        cls.addClassCleanup(cls._stop_api)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if cls.api.poll() is not None:
                raise RuntimeError("unprivileged API process exited during startup")
            try:
                if cls._request("/v1/health")[0] == 200:
                    break
            except (OSError, ssl.SSLError):
                pass
            time.sleep(0.15)
        else:
            raise RuntimeError("unprivileged API process did not become ready")

    @classmethod
    def _stop_gateway(cls):
        cls.gateway.shutdown()
        cls.gateway_thread.join(3)

    @classmethod
    def _stop_api(cls):
        if cls.api.poll() is None:
            cls.api.terminate()
            try:
                cls.api.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.api.kill()
                cls.api.wait(timeout=3)
        if cls.api.stderr:
            cls.api.stderr.close()

    @classmethod
    def _remove_containers(cls):
        if cls.created:
            subprocess.run(
                ["docker", "rm", "-f", *cls.created],
                timeout=30, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    @classmethod
    def _request(cls, path: str, *, method="GET", token=TOKEN):
        context = ssl._create_unverified_context()  # Ephemeral test certificate only.
        connection = http.client.HTTPSConnection("127.0.0.1", cls.port, timeout=5, context=context)
        headers = {"Authorization": "Bearer " + token} if token is not None else {}
        try:
            connection.request(method, path, headers=headers)
            result = connection.getresponse()
            return result.status, json.loads(result.read())
        finally:
            connection.close()

    def test_live_inventory_stopped_container_and_safe_inspect(self):
        status, result = self._request("/v1/containers")
        self.assertEqual(status, 200)
        self.assertEqual(result["source"], "docker-api")
        by_id = {item["id"]: item for item in result["containers"]}
        self.assertTrue(set(self.created).issubset(by_id))
        self.assertEqual(by_id[self.approved_id]["project"], self.approved_project)
        self.assertEqual(by_id[self.denied_id]["project"], self.denied_project)
        self.assertEqual(by_id[self.stopped_id]["status"], "exited")
        self.assertNotIn("Env", json.dumps(result))
        self.assertNotIn("HostConfig", json.dumps(result))
        status, detail = self._request(f"/v1/containers/{self.approved_id}")
        self.assertEqual(status, 200)
        self.assertEqual(detail["container"]["id"], self.approved_id)
        self.assertIn("restart_count", detail["container"])

    def test_project_logs_and_redaction(self):
        status, result = self._request(
            f"/v1/projects/{self.approved_project}/logs?since_minutes=5&limit=40"
        )
        self.assertEqual(status, 200)
        text = "\n".join(item["line"] for item in result["logs"])
        self.assertIn("visible-ready", text)
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("synthetic-private", text)
        status, denied = self._request(
            f"/v1/projects/{self.denied_project}/logs?since_minutes=5&limit=40"
        )
        self.assertEqual(status, 403)
        self.assertEqual(denied["error"], "LOG_PROJECT_DENIED")

    def test_mutation_and_arbitrary_routes_are_denied(self):
        before = docker("inspect", "--format", "{{.State.Status}}", self.approved_id)
        for method in ("POST", "DELETE", "PATCH", "PUT"):
            self.assertEqual(self._request("/v1/containers", method=method)[0], 405)
        for target in ("/v1/docker/containers/create", "/v1/containers/../containers",
                       "/v1/containers?all=0", "/v1/containers/%2e%2e"):
            self.assertNotEqual(self._request(target)[0], 200)
        self.assertFalse(_allowed_engine_route("/v1.41/containers/" + self.approved_id + "/kill"))
        self.assertEqual(docker("inspect", "--format", "{{.State.Status}}", self.approved_id), before)

    def test_api_identity_cannot_access_docker_daemon(self):
        code = (
            "import socket,sys; s=socket.socket(socket.AF_UNIX); "
            "\ntry: s.connect('/var/run/docker.sock')"
            "\nexcept PermissionError: sys.exit(0)"
            "\nexcept OSError: sys.exit(2)"
            "\nsys.exit(1)"
        )
        result = subprocess.run(
            ["runuser", "-u", "nobody", "--", sys.executable, "-c", code],
            capture_output=True, timeout=8,
        )
        self.assertEqual(result.returncode, 0, "API identity unexpectedly has Docker socket access")
        self.assertEqual(self.api.poll(), None, "unprivileged API service exited")

    def test_authentication_and_encrypted_listener(self):
        self.assertEqual(self._request("/v1/containers", token=None)[0], 401)
        self.assertEqual(self._request("/v1/containers", token="wrong")[0], 401)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            conn.request("GET", "/v1/health", headers={"Authorization": "Bearer " + TOKEN})
            with self.assertRaises((OSError, http.client.HTTPException)):
                conn.getresponse()
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

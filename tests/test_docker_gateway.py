"""Validate Docker route restrictions and Unix transport behavior."""
import json
import os
import socketserver
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler

from infrastructure_observer.docker_gateway import (
    API_PREFIX, MAX_JSON_BYTES, MAX_LOG_BYTES, DockerGatewayProvider,
    DockerUnixTransport, ObservationFailed, _allowed_engine_route, _decode_logs,
)
from infrastructure_observer.observer import Observer, project_of, projection


def fixture(i, project, **kwargs):
    cid = f"{i:064x}"
    return {"Id": cid, "Name": f"/fixture-{i}", "Image": "sha256:fixture",
            "Config": {"Image": "example/application:v1", "Labels": {"com.docker.compose.project": project},
                       "Env": ["API_KEY=private"], "Cmd": ["--password=private"], "Tty": kwargs.get("tty", False)},
            "Mounts": [{"Source": "/private/path"}], "HostConfig": {"Privileged": True},
            "State": {"Status": kwargs.get("status", "running"), "ExitCode": 0, "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Ports": {"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8443"}]}},
            "RestartCount": 0}


def frame(value, stream=1):
    b = value.encode()
    return bytes([stream, 0, 0, 0]) + len(b).to_bytes(4, "big") + b


class FakeDockerTransport:
    def __init__(self, records):
        self.records = {r["Id"]: r for r in records}
        self.calls = []
        self.log_data = {}

    def get(self, route, max_bytes):
        self.calls.append((route, max_bytes))
        if not _allowed_engine_route(route):
            raise ObservationFailed("route rejected")
        if route == API_PREFIX + "/containers/json?all=1":
            return json.dumps([{"Id": k} for k in self.records]).encode()
        seg = route.split("/")
        cid = seg[3]
        if seg[4] == "json":
            return json.dumps(self.records[cid]).encode()
        if seg[4].startswith("logs?"):
            return self.log_data.get(cid, b"")
        raise AssertionError("unexpected route")


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.approved = fixture(1, "approved-project")
        self.other = fixture(2, "private-project")
        self.transport = FakeDockerTransport([self.approved, self.other])
        self.provider = DockerGatewayProvider(self.transport, frozenset({"approved-project"}), clock=lambda: 1700000000)
        self.obs = Observer("example-host-a", self.provider)

    def test_inventory_only_three_fixed_get_families(self):
        code, result = self.obs.handle("GET", "/v1/containers")
        self.assertEqual(code, 200)
        self.assertEqual(len(result["containers"]), 2)
        self.assertTrue(all(_allowed_engine_route(x[0]) for x in self.transport.calls))
        self.assertEqual(self.transport.calls[0][0], API_PREFIX + "/containers/json?all=1")
        self.assertEqual(result["containers"][0]["project"], "approved-project")
        self.assertEqual(result["containers"][0]["ports"][0]["PublicPort"], 8443)
        for dangerous in ("API_KEY", "private/path", "Privileged", "password", "HostConfig", "Mounts"):
            self.assertNotIn(dangerous, str(result))

    def test_inspect_requires_exact_id(self):
        original_id = self.approved["Id"]
        self.transport.records[original_id]["Id"] = self.other["Id"]
        with self.assertRaises(ObservationFailed):
            self.provider._inspect(original_id)
        with self.assertRaises(ObservationFailed):
            self.provider._inspect("../" + self.other["Id"])

    def test_log_allowed_with_fresh_verification(self):
        self.transport.log_data[self.approved["Id"]] = frame("started\n") + frame("token=secret\n", 2)
        code, result = self.obs.handle("GET", "/v1/projects/approved-project/logs?since_minutes=5&limit=5")
        self.assertEqual(code, 200)
        self.assertEqual(len(result["logs"]), 2)
        self.assertNotIn("token=secret", str(result["logs"]))
        self.assertIn("[REDACTED]", str(result))
        self.assertTrue(any("/logs?" in path for path, _ in self.transport.calls))

    def test_unapproved_log_request_never_reaches_docker_logs(self):
        self.assertEqual(self.obs.handle("GET", "/v1/projects/private-project/logs?since_minutes=5&limit=5")[0], 403)
        with self.assertRaises(ObservationFailed):
            self.provider.get_logs(self.other["Id"], 5, 5)
        self.assertFalse(any("/logs?" in path for path, _ in self.transport.calls))

    def test_membership_revoked_before_log_fetch(self):
        self.provider.list_containers()
        self.transport.records[self.approved["Id"]]["Config"]["Labels"]["com.docker.compose.project"] = "private-project"
        with self.assertRaises(ObservationFailed):
            self.provider.get_logs(self.approved["Id"], 5, 5)
        self.assertFalse(any("/logs?" in path for path, _ in self.transport.calls))

    def test_error_does_not_expose_exception_or_credential(self):
        self.transport.records[self.approved["Id"]]["Id"] = "bad"
        code, result = self.obs.handle("GET", "/v1/containers")
        self.assertEqual(code, 503)
        self.assertNotIn("bad", str(result))
        self.assertTrue(result["partial"])

    def test_mismatching_list_and_inspect_project_denies(self):
        raw = fixture(3, "approved-project")
        raw["Labels"] = {"com.docker.compose.project": "private-project"}
        self.assertIsNone(project_of(raw))

    def test_reject_method_and_routes_even_if_bypassed_observer(self):
        cid = self.approved["Id"]
        routes = [f"{API_PREFIX}/containers/{cid}/archive?path=/root",
                  f"{API_PREFIX}/containers/{cid}/exec", f"{API_PREFIX}/containers/{cid}/start",
                  f"{API_PREFIX}/containers/{cid}/json?size=1", f"{API_PREFIX}/containers/{cid}/json/../logs",
                  f"{API_PREFIX}/containers/{cid}/json%2f../logs", f"{API_PREFIX}/containers/{cid}/logs?stdout=1",
                  f"{API_PREFIX}/containers/{cid}/logs?stdout=1&stderr=1&timestamps=0&follow=0&since=1&tail=1000",
                  "/v1.41/containers/json?all=0", "/info", f"{API_PREFIX}/containers/{cid}/json#bad"]
        for route in routes:
            with self.subTest(route=route):
                self.assertFalse(_allowed_engine_route(route))
        self.assertFalse(any(_allowed_engine_route(x) for x in ["//containers/json?all=1", "https://example.test/v1.41/containers/json?all=1"]))

    def test_log_frame_errors_fail_closed(self):
        for payload in (b"random raw text", b"\x01\x00\x00\x00\x00\x00\x00\x0asmall", frame("hi")[:-1]):
            with self.subTest(payload=payload):
                with self.assertRaises(ObservationFailed):
                    _decode_logs(payload, False)
        self.assertEqual(_decode_logs(b"some text\n", True), ["some text"])

    def test_limits_on_inventory_and_payload(self):
        transport = FakeDockerTransport([fixture(n+1,"approved-project") for n in range(201)])
        with self.assertRaises(ObservationFailed):
            DockerGatewayProvider(transport, frozenset()).list_containers()
        with self.assertRaises(ObservationFailed):
            self.provider.get_logs(self.approved["Id"], 16, 10)
        with self.assertRaises(ObservationFailed):
            self.provider.get_logs(self.approved["Id"], 1, 101)


class _FakeUnixServer(socketserver.UnixStreamServer):
    allow_reuse_address = True


class RealUnixSocketTransportTests(unittest.TestCase):
    def test_get_only_over_disposable_unix_daemon(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(("GET", self.path))
                body = b'[{"Id":"' + b"a" * 64 + b'"}]'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def do_POST(self):
                requests.append(("POST", self.path))
                self.send_response(200)
                self.end_headers()
            def log_message(self, *_):
                pass
        with tempfile.TemporaryDirectory() as temp:
            sock = os.path.join(temp,"fixture.sock")
            server = _FakeUnixServer(sock, Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                transport = DockerUnixTransport(sock)
                body = transport.get(API_PREFIX + "/containers/json?all=1", MAX_JSON_BYTES)
                self.assertIn(b'"Id"', body)
                for route in (API_PREFIX + "/containers/create", API_PREFIX + "/containers/a/archive?path=/", "/info"):
                    with self.assertRaises(ObservationFailed):
                        transport.get(route, MAX_JSON_BYTES)
                self.assertEqual(requests, [("GET", API_PREFIX + "/containers/json?all=1")])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(3)


if __name__ == "__main__":
    unittest.main()

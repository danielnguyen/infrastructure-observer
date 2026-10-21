"""Exercise authenticated API forwarding and the local Unix-socket boundary."""

import http.client
import json
import os
import pathlib
import stat
import tempfile
import threading
import unittest

from infrastructure_observer.observer import FixtureProvider, Observer
from infrastructure_observer.service import (
    AuthenticatedAPIServer, GatewayClient, LocalGatewayServer, _token_from_file,
    permitted_observation_path,
)


TOKEN = 'development-token-' + 'a' * 48
CONTAINER = 'a' * 64


def fixture():
    return {
        'Id': CONTAINER,
        'Name': '/demo',
        'Image': 'sha256:example',
        'Config': {'Image': 'example/image:1', 'Env': ['PASSWORD=private'],
                   'Labels': {'com.docker.compose.project': 'approved-project'}},
        'State': {'Status': 'running', 'Health': {'Status': 'healthy'}},
    }


class CountingProvider(FixtureProvider):
    def __init__(self):
        super().__init__([fixture()], {CONTAINER: ['started', 'token=secret']})
        self.inventory_requests = 0
        self.log_requests = 0

    def list_containers(self):
        self.inventory_requests += 1
        return super().list_containers()

    def get_logs(self, exact_id, since_minutes, limit):
        self.log_requests += 1
        return super().get_logs(exact_id, since_minutes, limit)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temp.name)
        os.chmod(self.directory, 0o750)
        self.provider = CountingProvider()
        self.gateway = LocalGatewayServer(
            str(self.directory / 'gateway.sock'),
            Observer('example-host-a', self.provider, frozenset({'approved-project'})),
        )
        self.gateway_thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.gateway_thread.start()
        self.client = GatewayClient(str(self.directory / 'gateway.sock'))
        # HTTP is deliberate only in this loopback unit test. The service CLI
        # requires a TLS key/cert before it can start the actual API listener.
        self.api = AuthenticatedAPIServer(('127.0.0.1', 0), self.client, TOKEN)
        self.api_thread = threading.Thread(target=self.api.serve_forever, daemon=True)
        self.api_thread.start()

    def tearDown(self):
        self.api.shutdown()
        self.api.server_close()
        self.api_thread.join(2)
        self.gateway.shutdown()
        self.gateway.server_close()
        self.gateway_thread.join(2)
        self.temp.cleanup()

    def request(self, method, path, token=None):
        client = http.client.HTTPConnection('127.0.0.1', self.api.server_port, timeout=3)
        headers = {'Authorization': 'Bearer ' + token} if token is not None else {}
        try:
            client.request(method, path, headers=headers)
            res = client.getresponse()
            data = json.loads(res.read())
            return res.status, data, dict(res.getheaders())
        finally:
            client.close()

    def test_valid_inventory_authentication_and_output_projection(self):
        status, body, headers = self.request('GET', '/v1/containers', TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(body['containers'][0]['project'], 'approved-project')
        self.assertNotIn('PASSWORD', str(body))
        self.assertNotIn('private', str(body))
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertGreater(self.provider.inventory_requests, 0)

    def test_unauthorized_never_reaches_gateway(self):
        initial = self.provider.inventory_requests
        for token in (None, 'not-authorized', TOKEN + 'x'):
            self.assertEqual(self.request('GET', '/v1/containers', token)[0], 401)
        self.assertEqual(self.provider.inventory_requests, initial)

    def test_only_get_and_allowlisted_paths(self):
        initial = self.provider.inventory_requests
        for path in ('/v1/docker/create', '//v1/containers', '/v1/containers/%2e%2e',
                     '/v1/containers?anything=1', '/v1/projects/approved-project/logs?limit=5&since_minutes=1'):
            self.assertNotEqual(self.request('GET', path, TOKEN)[0], 200)
        for method in ('POST', 'DELETE', 'PUT', 'PATCH'):
            self.assertEqual(self.request(method, '/v1/containers', TOKEN)[0], 405)
        self.assertEqual(self.provider.inventory_requests, initial)

    def test_project_log_permission_and_redaction(self):
        status, body, _ = self.request('GET', '/v1/projects/approved-project/logs?since_minutes=5&limit=10', TOKEN)
        self.assertEqual(status, 200)
        self.assertIn('[REDACTED]', str(body))
        self.assertNotIn('token=secret', str(body['logs']))
        self.assertEqual(self.provider.log_requests, 1)
        status, _, _ = self.request('GET', '/v1/projects/private-project/logs?since_minutes=5&limit=10', TOKEN)
        self.assertEqual(status, 403)
        self.assertEqual(self.provider.log_requests, 1)

    def test_gateway_unavailable_reports_partial_not_clean(self):
        self.gateway.shutdown()
        self.gateway.server_close()
        status, body, _ = self.request('GET', '/v1/containers', TOKEN)
        self.assertEqual(status, 503)
        self.assertTrue(body['partial'])

    def test_gateway_socket_path_cannot_be_replaced(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.directory / 'gateway.sock').st_mode), 0o660)
        with self.assertRaises(FileExistsError):
            LocalGatewayServer(str(self.directory / 'gateway.sock'), Observer('example-host-a', self.provider))

    def test_path_grammar(self):
        self.assertTrue(permitted_observation_path('/v1/health'))
        self.assertTrue(permitted_observation_path('/v1/projects/approved-project/logs?since_minutes=1&limit=1'))
        for p in ('http://localhost/v1/health', '/v1/docker/info', '/v1/containers/../health',
                  '/v1/projects/approved-project/logs?since_minutes=1&limit=1&limit=1',
                  '/v1/projects/approved-project/logs?since_minutes=1&limit=1%26method=POST'):
            self.assertFalse(permitted_observation_path(p))


class CredentialAndDirectoryTests(unittest.TestCase):
    def test_credentials_must_be_private_regular_files(self):
        with tempfile.TemporaryDirectory() as root:
            p = pathlib.Path(root) / 'credential'
            p.write_text(TOKEN + '\n')
            os.chmod(p, 0o600)
            self.assertEqual(_token_from_file(str(p)), TOKEN)
            os.chmod(p, 0o644)
            with self.assertRaises(ValueError):
                _token_from_file(str(p))
            os.chmod(p, 0o600)
            symlink = pathlib.Path(root) / 'link'
            symlink.symlink_to(p)
            with self.assertRaises((ValueError, OSError)):
                _token_from_file(str(symlink))

    def test_world_accessible_gateway_directory_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o777)
            with self.assertRaises(ValueError):
                LocalGatewayServer(str(pathlib.Path(root) / 'gateway.sock'), Observer('example-host-a', FixtureProvider([])))


if __name__ == '__main__':
    unittest.main()


class TLSTransportTests(unittest.TestCase):
    def test_tls_handshake_and_bearer_token(self):
        import shutil
        import ssl
        import subprocess

        if shutil.which('openssl') is None:
            self.skipTest('openssl unavailable for ephemeral local certificate')
        with tempfile.TemporaryDirectory() as root:
            cert = os.path.join(root, 'cert.pem')
            key = os.path.join(root, 'key.pem')
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-subj', '/CN=localhost', '-days', '1', '-keyout', key, '-out', cert
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, check=True)
            gateway = type('StubClient', (), {
                'request': lambda self, path: (200, {'requested': path})
            })()
            api = AuthenticatedAPIServer(('127.0.0.1', 0), gateway, TOKEN)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            api.socket = context.wrap_socket(api.socket, server_side=True)
            thread = threading.Thread(target=api.serve_forever, daemon=True)
            thread.start()
            try:
                unverified = ssl._create_unverified_context()
                client = http.client.HTTPSConnection('127.0.0.1', api.server_port, context=unverified)
                try:
                    client.request('GET', '/v1/health', headers={'Authorization': 'Bearer ' + TOKEN})
                    res = client.getresponse()
                    self.assertEqual(res.status, 200)
                    self.assertEqual(json.loads(res.read()), {'requested': '/v1/health'})
                finally:
                    client.close()
                plain = http.client.HTTPConnection('127.0.0.1', api.server_port, timeout=1)
                try:
                    plain.request('GET', '/v1/health', headers={'Authorization': 'Bearer ' + TOKEN})
                    with self.assertRaises((OSError, http.client.HTTPException)):
                        plain.getresponse()
                finally:
                    plain.close()
            finally:
                api.shutdown()
                api.server_close()
                thread.join(2)

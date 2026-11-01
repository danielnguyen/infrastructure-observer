"""Synthetic reports, bounded transport, and disposable loopback TLS only."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from infrastructure_observer import status
from infrastructure_observer.observer import FixtureProvider, Observer
from infrastructure_observer.service import AuthenticatedAPIServer

TOKEN = 'synthetic-test-credential-' + 'x' * 32


def inventory():
    containers = []
    for i, (name, project, runtime, health) in enumerate([
        ('zeta', 'alpha', 'running', 'healthy'),
        ('alpha', 'alpha', 'running', None),
        ('bad', 'beta', 'running', 'unhealthy'),
        ('stopped', 'beta', 'exited', None),
        ('missing', None, None, None),
    ]):
        containers.append({'Id': f'{i:064x}', 'Name': name,
                           'Config': {'Labels': {'com.docker.compose.project': project}},
                           'State': {'Status': runtime, 'Health': {'Status': health}}})
    _, value = Observer('example-host-a', FixtureProvider(containers)).handle('GET', '/v1/containers')
    value['observed_at'] = '2026-01-02T03:04:05+00:00'
    return value


class ReportTests(unittest.TestCase):
    def test_group_order_summary_and_unknowns(self):
        value = inventory()
        text, code = status.report(value, TOKEN)
        self.assertEqual(code, 1)
        self.assertIn('Host: example-host-a | Observed: 2026-01-02T03:04:05+00:00 (UTC)', text)
        self.assertLess(text.index('  alpha ['), text.index('  zeta ['))
        self.assertLess(text.index('Project: alpha'), text.index('Project: beta'))
        self.assertIn('Project: [unknown/unlabelled]', text)
        self.assertIn('runtime=exited', text)
        self.assertIn('runtime=unknown/unavailable', text)
        self.assertIn('health=no health check reported', text)
        self.assertIn('health=unhealthy', text)
        self.assertIn('Total: 5 containers; 3 flagged; 1 not running; 1 unhealthy; 1 unknown; 3 with no health check', text)
        value['containers'].reverse()
        self.assertEqual(status.report(value, TOKEN), (text, code))

    def test_healthy_no_check_and_empty(self):
        for health in ('healthy', None):
            value = inventory()
            value['source'] = 'docker-api'
            value['containers'] = [value['containers'][0]]
            value['containers'][0]['health'] = health
            text, code = status.report(value, TOKEN)
            self.assertEqual(code, 0)
            if health is None:
                self.assertIn('health=no health check reported', text)
                self.assertNotIn('health=healthy', text)
        value['containers'] = []
        text, code = status.report(value, TOKEN)
        self.assertEqual(code, 0)
        self.assertIn('Inventory is empty', text)
        self.assertNotIn('health=healthy', text)

    def test_all_nonrunning_and_unknown_states_flagged(self):
        for runtime, health in [('paused', 'healthy'), ('dead', None), ('created', None),
                                ('restarting', None), ('removing', None), ('new-state', 'healthy'),
                                ('running', 'new-health'), ('running', 'starting')]:
            value = inventory()
            value['containers'] = [value['containers'][0]]
            value['containers'][0].update(status=runtime, health=health)
            self.assertEqual(status.report(value, TOKEN)[1], 1)

    def test_invalid_and_partial_never_report(self):
        mutations = [lambda v: v.update(partial=True), lambda v: v.pop('partial'),
                     lambda v: v.update(partial=0), lambda v: v.update(warnings=['secret']),
                     lambda v: v.update(host=None), lambda v: v.update(source='invalid'),
                     lambda v: v.update(observed_at='2026-01-02'),
                     lambda v: v.update(containers={}),
                     lambda v: v['containers'].append(v['containers'][0]),
                     lambda v: v['containers'][0].pop('health'),
                     lambda v: v['containers'][0].update(status={}),
                     lambda v: v['containers'][0].update(project=[]),
                     lambda v: v['containers'][0].update(id='short')]
        for mutate in mutations:
            value = inventory()
            mutate(value)
            with self.assertRaises(ValueError):
                status.report(value, TOKEN)

    def test_terminal_bounds_and_reflected_token(self):
        value = inventory()
        value['containers'][0]['name'] = TOKEN
        value['containers'][1]['name'] = '\x1b[31m\n\r\x00\u202e' + 'x' * 5000
        text, _ = status.report(value, TOKEN)
        self.assertNotIn(TOKEN, text)
        for control in ('\x1b', '\r', '\x00', '\u202e'):
            self.assertNotIn(control, text)
        self.assertLess(max(map(len, text.splitlines())), 200)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.token = Path(self.temp.name) / 'token'
        self.token.write_text(TOKEN)
        self.token.chmod(0o600)
        self.args = ['--url', 'https://observer.example:8765', '--token-file', str(self.token)]

    def run_cli(self, args=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = status.main(self.args if args is None else args)
        return code, out.getvalue(), err.getvalue()

    def test_fixed_route_verified_tls_timeout_and_size(self):
        with patch.object(status.http.client, 'HTTPSConnection') as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps(inventory()).encode()
            self.assertEqual(self.run_cli()[0], 1)
            args, kwargs = factory.call_args
            self.assertEqual(args, ('observer.example', 8765))
            self.assertEqual(kwargs['timeout'], 5.0)
            self.assertTrue(kwargs['context'].check_hostname)
            self.assertEqual(kwargs['context'].verify_mode, ssl.CERT_REQUIRED)
            connection.request.assert_called_once_with('GET', '/v1/containers', headers={
                'Authorization': 'Bearer ' + TOKEN, 'Connection': 'close', 'Accept': 'application/json'})
            response.read.assert_called_once_with(status.MAX_RESPONSE_BYTES + 1)
            connection.close.assert_called_once()

    def test_http_failures_redirects_malformed_and_oversize(self):
        for code in (301, 302, 307, 308, 401, 403, 429, 503):
            with self.subTest(code=code), patch.object(status.http.client, 'HTTPSConnection') as factory:
                response = factory.return_value.getresponse.return_value
                response.status = code
                response.read.return_value = TOKEN.encode()
                result, out, err = self.run_cli()
                self.assertEqual(result, 2)
                self.assertEqual(out, '')
                self.assertNotIn(TOKEN, err)
                response.read.assert_not_called()
                factory.return_value.request.assert_called_once()
        for raw in (b'{', b'null', b'[]', b'{}', b'\xff', b'{"partial":true,"partial":false}', b'{"extra":NaN}', b'x' * (status.MAX_RESPONSE_BYTES + 1)):
            with self.subTest(raw=raw[:10]), patch.object(status.http.client, 'HTTPSConnection') as factory:
                response = factory.return_value.getresponse.return_value
                response.status, response.read.return_value = 200, raw
                self.assertEqual(self.run_cli()[0], 2)

    def test_network_errors_suppressed(self):
        for error in (OSError(TOKEN), TimeoutError(TOKEN), ssl.SSLError(TOKEN)):
            with patch.object(status.http.client, 'HTTPSConnection') as factory:
                factory.return_value.request.side_effect = error
                code, out, err = self.run_cli()
                self.assertEqual(code, 2)
                self.assertEqual(out, '')
                self.assertNotIn(TOKEN, err)

    def test_reject_non_origins_without_network(self):
        for url in ('http://observer.example', 'https://user:secret@observer.example',
                    'https://observer.example/v1/health', 'https://observer.example?token=secret',
                    'https://observer.example/#fragment', 'https://observer.example:0',
                    '\nhttps://observer.example', 'https://observer.example:99999'):
            with patch.object(status.http.client, 'HTTPSConnection') as factory:
                self.assertEqual(self.run_cli(['--url', url, '--token-file', str(self.token)])[0], 2)
                factory.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            status.main(self.args + ['--insecure', TOKEN])
        self.assertNotIn(TOKEN, err.getvalue())

    def test_unsafe_missing_and_unreadable_credentials(self):
        paths = [str(self.token) + '-missing', self.temp.name]
        link = Path(self.temp.name) / 'link'
        link.symlink_to(self.token)
        paths.append(str(link))
        fifo = Path(self.temp.name) / 'fifo'
        os.mkfifo(fifo, 0o600)
        paths.append(str(fifo))
        for path in paths:
            self.assertEqual(self.run_cli(['--url', 'https://observer.example', '--token-file', path])[0], 2)
        self.token.chmod(0o644)
        self.assertEqual(self.run_cli()[0], 2)
        self.token.chmod(0o600)
        for content in ('short', 'x' * 257, 'x' * 32 + '\ninvalid', 'x' * 32 + '\x00'):
            self.token.write_text(content)
            self.assertEqual(self.run_cli()[0], 2)
        with patch.object(status, '_token_from_file', side_effect=PermissionError(TOKEN)):
            code, out, err = self.run_cli()
            self.assertEqual(code, 2)
            self.assertNotIn(TOKEN, err)


@unittest.skipUnless(shutil.which('openssl'), 'openssl needed for ephemeral TLS fixture')
class TLSIntegrationTests(unittest.TestCase):
    def test_real_certificate_trust_hostname_and_authentication(self):
        with tempfile.TemporaryDirectory() as root:
            cert, key = str(Path(root) / 'cert.pem'), str(Path(root) / 'key.pem')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-days', '1', '-keyout', key, '-out', cert],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, check=True)
            gateway = Mock()
            gateway.request.return_value = (200, inventory())
            api = AuthenticatedAPIServer(('127.0.0.1', 0), gateway, TOKEN)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            api.socket = context.wrap_socket(api.socket, server_side=True)
            thread = threading.Thread(target=api.serve_forever, daemon=True)
            thread.start()
            try:
                url = f'https://localhost:{api.server_port}'
                self.assertEqual(status.fetch(url, cert, TOKEN), inventory())
                gateway.request.assert_called_once_with('/v1/containers')
                with self.assertRaises(ssl.SSLCertVerificationError):
                    status.fetch(url, None, TOKEN)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    status.fetch(f'https://127.0.0.1:{api.server_port}', cert, TOKEN)
                for token in ('', 'wrong-token'):
                    with self.assertRaises(ValueError):
                        status.fetch(url, cert, token)
                gateway.request.assert_called_once()
            finally:
                api.shutdown()
                api.server_close()
                thread.join(2)

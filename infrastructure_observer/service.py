"""Local observation service and authenticated TLS API boundary."""

from __future__ import annotations

import argparse
import hmac
import http.client
import json
import os
import re
import socket
import socketserver
import ssl
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .docker_gateway import DockerGatewayProvider, DockerUnixTransport
from .observer import Observer, PROJECT_RE

MAX_RESPONSE_BYTES = 256 * 1024
MAX_REQUEST_TARGET_BYTES = 256
MAX_API_THREADS = 8


def permitted_observation_path(path: str) -> bool:
    """Check the public read-only API grammar before crossing a trust boundary."""
    if not isinstance(path, str) or len(path) > MAX_REQUEST_TARGET_BYTES:
        return False
    if any(c in path for c in ('%', '\\', '//', '#', '\r', '\n')):
        return False
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith('/'):
        return False
    if parsed.path in ('/v1/health', '/v1/containers', '/v1/projects'):
        return not parsed.query
    if re.fullmatch(r'/v1/containers/[a-f0-9]{64}', parsed.path):
        return not parsed.query
    if re.fullmatch(r'/v1/projects/[a-z][a-z0-9-]{0,62}/logs', parsed.path):
        # Keep the request grammar exact. Observer checks the numeric bounds.
        return re.fullmatch(r'since_minutes=[0-9]{1,2}&limit=[0-9]{1,3}', parsed.query) is not None
    return False


def _respond(handler: BaseHTTPRequestHandler, status: int, value: dict) -> None:
    raw = json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(raw) > MAX_RESPONSE_BYTES:
        status = 503
        raw = b'{"error":"RESPONSE_LIMIT","partial":true}'
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(raw)))
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('X-Content-Type-Options', 'nosniff')
    handler.end_headers()
    try:
        handler.wfile.write(raw)
    except OSError:
        pass


class _LimitedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = True

    def process_request(self, request, client_address):
        if not self._workers.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()


class LocalGatewayServer(_LimitedThreadingMixIn, socketserver.UnixStreamServer):
    """The trusted process owns the Docker transport and the IPC socket."""

    def __init__(self, socket_path: str, observer: Observer, max_workers: int = MAX_API_THREADS):
        self._workers = threading.BoundedSemaphore(max_workers)
        self.observer = observer
        self.socket_path = socket_path
        parent = Path(socket_path).parent
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or (info.st_mode & 0o027)):
            raise ValueError('gateway socket directory must be private')
        # Never unlink a pre-existing path: a stale socket is an operator issue.
        if os.path.lexists(socket_path):
            raise FileExistsError('gateway socket already exists')
        original_umask = os.umask(0o117)
        try:
            super().__init__(socket_path, _gateway_handler())
        finally:
            os.umask(original_umask)

    def server_close(self):
        try:
            super().server_close()
        finally:
            # Socket cleanup is only allowed when it is still the same socket inode.
            try:
                current = os.lstat(self.socket_path)
                if (stat.S_ISSOCK(current.st_mode) and current.st_ino == self._socket_inode):
                    os.unlink(self.socket_path)
            except (AttributeError, FileNotFoundError):
                pass

    def server_activate(self):
        super().server_activate()
        self._socket_inode = os.lstat(self.socket_path).st_ino


def _gateway_handler():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def parse_request(self):
            if not super().parse_request():
                return False
            if self.raw_requestline.split(b' ')[1].startswith(b'//'):
                _respond(self, 400, {'error': 'BAD_PATH'})
                return False
            return True

        def do_GET(self):
            if not permitted_observation_path(self.path):
                return _respond(self, 404, {'error': 'NOT_FOUND'})
            status, body = self.server.observer.handle('GET', self.path)
            _respond(self, status, body)

        def do_POST(self):
            _respond(self, 405, {'error': 'METHOD_DENIED'})

        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST

        def log_message(self, *_args):
            pass

    return Handler


class GatewayClient:
    """The API can reach this socket, but has no access to the Docker socket."""

    def __init__(self, socket_path: str, timeout: float = 4.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def request(self, path: str) -> tuple[int, dict]:
        if not permitted_observation_path(path):
            return 404, {'error': 'NOT_FOUND'}

        class UnixConnection(http.client.HTTPConnection):
            def connect(inner_self):
                inner_self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                inner_self.sock.settimeout(inner_self.timeout)
                inner_self.sock.connect(self.socket_path)

        connection = UnixConnection('localhost', timeout=self.timeout)
        try:
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            if response.status not in (200, 400, 403, 404, 405, 503):
                raise ValueError('invalid gateway status')
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError('gateway response too large')
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError('invalid gateway response')
            return response.status, result
        except (OSError, ValueError, http.client.HTTPException, TimeoutError):
            return 503, {'error': 'OBSERVATION_UNAVAILABLE', 'partial': True}
        finally:
            connection.close()


class AuthenticatedAPIServer(_LimitedThreadingMixIn, HTTPServer):
    """API listener deliberately receives only a GatewayClient, never Docker credentials."""

    def __init__(self, address, gateway: GatewayClient, token: str, max_workers: int = MAX_API_THREADS):
        if not isinstance(token, str) or len(token) < 32 or any(ch.isspace() for ch in token):
            raise ValueError('API token must be at least 32 non-whitespace characters')
        self._workers = threading.BoundedSemaphore(max_workers)
        self.gateway = gateway
        self.api_token = token
        super().__init__(address, _api_handler())


def _api_handler():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def parse_request(self):
            if not super().parse_request():
                return False
            if self.raw_requestline.split(b' ')[1].startswith(b'//'):
                _respond(self, 400, {'error': 'BAD_PATH'})
                return False
            return True

        def _authorized(self):
            provided = self.headers.get_all('Authorization', [])
            if len(provided) != 1:
                return False
            value = provided[0]
            return len(value) < 256 and hmac.compare_digest(value, 'Bearer ' + self.server.api_token)

        def _request(self, method: str):
            if not self._authorized():
                return _respond(self, 401, {'error': 'UNAUTHORIZED'})
            if method != 'GET':
                return _respond(self, 405, {'error': 'METHOD_DENIED'})
            if not permitted_observation_path(self.path):
                return _respond(self, 404, {'error': 'NOT_FOUND'})
            status, result = self.server.gateway.request(self.path)
            _respond(self, status, result)

        def do_GET(self): self._request('GET')
        def do_POST(self): self._request('POST')
        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST

        def log_message(self, *_args):
            pass

    return Handler


def _token_from_file(path: str) -> str:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o077):
            raise ValueError('API credential must be a private regular file')
        if info.st_size > 256:
            raise ValueError('API credential file is too large')
        with os.fdopen(os.dup(fd), encoding='utf-8') as handle:
            value = handle.read().rstrip('\r\n')
        if len(value) < 32 or len(value) > 256 or any(ch.isspace() for ch in value):
            raise ValueError('invalid API credential')
        return value
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description='Infrastructure observation service')
    sub = parser.add_subparsers(dest='service', required=True)
    gateway_args = sub.add_parser('gateway')
    gateway_args.add_argument('--socket', required=True)
    gateway_args.add_argument('--docker-socket', default='/var/run/docker.sock')
    gateway_args.add_argument('--host', required=True)
    gateway_args.add_argument('--log-project', action='append', default=[])
    api_args = sub.add_parser('api')
    api_args.add_argument('--gateway-socket', required=True)
    api_args.add_argument('--listen-ip', required=True)
    api_args.add_argument('--port', type=int, default=8765)
    api_args.add_argument('--tls-cert', required=True)
    api_args.add_argument('--tls-key', required=True)
    api_args.add_argument('--token-file', required=True)
    args = parser.parse_args()

    if args.service == 'gateway':
        projects = frozenset(args.log_project)
        if any(PROJECT_RE.fullmatch(name) is None for name in projects):
            parser.error('invalid approved project name')
        provider = DockerGatewayProvider(DockerUnixTransport(args.docker_socket), projects)
        observer = Observer(args.host, provider, approved_log_projects=projects)
        with LocalGatewayServer(args.socket, observer) as server:
            server.serve_forever()
    else:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            parser.error('LAN API process must not run as root')
        token = _token_from_file(args.token_file)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        with AuthenticatedAPIServer((args.listen_ip, args.port), GatewayClient(args.gateway_socket), token) as server:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.serve_forever()


if __name__ == '__main__':
    main()

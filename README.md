# Infrastructure Observer

A small service for bounded container inventory, container metadata, and approved-project diagnostic logs. The interface exposes no Docker administration or arbitrary-command endpoints.

## Components

- `infrastructure_observer/observer.py` — inventory, metadata projection and project-scoped log policy
- `infrastructure_observer/docker_gateway.py` — constrained Docker Engine client
- `infrastructure_observer/service.py` — local Unix-socket reader service and authenticated TLS API
- `tests/` — synthetic Docker and service-boundary tests
- `planning/` — security assessments, implementation decisions and follow-on work

One codebase supports two service roles on a host: a trusted Docker reader behind a private Unix socket, and a separate unprivileged HTTPS API. The API never needs access to the Docker socket.

## Tests

Requires Python 3.11 or later; uses only the standard library. An optional TLS test invokes locally installed OpenSSL to create a temporary test certificate.

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

An in-memory fixture server is also available on loopback:

```sh
python3 -m infrastructure_observer.observer --offline-fixture --host example-host-a
```

## Container packaging

The [Compose stack candidate](deployment/README.md) runs the trusted Docker reader and unprivileged HTTPS API as separate services sharing a private IPC volume. It is exercised on disposable CI runners, not authorized for production use. The rootful Docker reader's residual authority remains a security acceptance gate.

The authenticated API uses a bounded, in-memory request limiter (24-request burst, then one new request per second). A rejected observation receives HTTP 429; callers should not aggressively retry.

## Security and deployment status

The code enforces restricted API operations and separates network access from the Docker reader. **It is not yet approved for production deployment.** A process with unrestricted Docker socket access retains host-administrative authority if compromised. Real-world container isolation, private network policies, certificate and credential provisioning, Docker compatibility and Portainer stack identity still require independent validation.

Details and acceptance gates are in [planning/IPC_TRUST_BOUNDARY.md](planning/IPC_TRUST_BOUNDARY.md). Do not store real hostnames, IP addresses, log contents, credentials or stack inventories in this public repository.

## Docker Engine integration checks

The [Docker integration workflow](.github/workflows/docker-integration.yml) runs the application tests and exercises real Docker Engine behavior on a disposable GitHub-hosted Linux runner. The integration harness creates temporary containers, runs the observation API as an unprivileged OS user, checks Docker socket isolation and authorization, then removes its containers. See [testing details](planning/REAL_DOCKER_VALIDATION.md).

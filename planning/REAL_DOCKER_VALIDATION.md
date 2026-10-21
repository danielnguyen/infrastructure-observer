# Real Docker Engine integration validation

This validation runs only on disposable GitHub-hosted Ubuntu VMs, without any access to production hosts, private networks, or operational credentials.

## Coverage

- Actual Docker Engine list/inspect/log endpoints, including a stopped container
- Compose project-label membership and approved-project-only diagnostic logs
- Sanitized inventory and inspect projections, rather than raw Docker data
- API authentication and denial of mutation methods and arbitrary routes
- Reader Unix-socket connection and unprivileged API service as separate Linux processes
- Operating-system denial of Docker socket access to the API's Linux account
- TLS listener behavior with a locally generated disposable test certificate
- Container removal after each run, with runner VM deletion as an independent fallback

The test harness uses privileged Docker CLI operations **only to create and dispose of its own synthetic containers**. This does not grant the observer a Docker mutation interface.

## Trust and release limitations

A passing workflow validates compatibility and some permission boundaries on the GitHub runner. It does not establish that the socket-bearing Docker reader is safe if compromised: that process still has Docker administrative privileges. It also does not prove containerization, mount isolation, group permissions, network firewall policy, certificates, operational update procedures, or Portainer behavior on either production host.

The test service binds to runner loopback only. The API listener is exercised with a disposable self-signed TLS certificate and a generated test-only bearer token. These test credentials must never be deployed.

The Docker API request prefix remains pinned to v1.41 until separate host compatibility checks; the test will fail rather than silently adjust the allowed routes. The workflow uses `ubuntu-24.04` to avoid automatic runner-image migration.

## Running

Offline tests (no Docker needed):

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Real Docker testing is deliberately opt-in. Execute only on a disposable Linux machine with Docker Engine and `sudo`/`runuser` access:

```sh
sudo docker pull busybox:1.36.1
sudo INFRA_OBSERVER_REAL_DOCKER=1 python3 -m unittest tests.test_engine_integration -v
```

The integration test checks for root and system prerequisites explicitly instead of silently skipping when enabled.

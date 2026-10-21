# Infrastructure Observer (offline prototype)

Minimal, security-conscious observer API for reporting Docker container inventory and approved project logs to an aggregator such as PAB.

**Current state: offline fixture prototype only. Not deployable.** This repository has no production Docker adapter, Docker daemon credentials, Portainer connectivity, authentication/TLS or production deployment configuration.

- [Boundary and offline build brief](BOUNDARY_AND_OFFLINE_BUILD.md)
- [Offline milestone task](CODEX_OFFLINE_MILESTONE_A.md)
- [Prototype and tests](offline-prototype/README.md)

Run synthetic tests:

```sh
cd offline-prototype
python3 -m unittest discover -s . -p 'test_*.py' -v
```

Host identifiers and project names in this public repo are illustrative. Keep real host addresses, service inventories, local permissions and credentials private. Do not mount Docker sockets or deploy this prototype to real servers. The Docker daemon privilege boundary requires its own disposable-environment validation before production use.

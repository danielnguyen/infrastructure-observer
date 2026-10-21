# Infrastructure Observer

An HTTP interface for bounded container inventory, container metadata, and approved-project diagnostic logs. The application has no general-purpose Docker proxy endpoint or mutation API.

## Repository layout

- `infrastructure_observer/` — observation HTTP handlers and constrained Docker Engine reader
- `tests/` — synthetic authorization and Unix-socket tests
- `planning/` — architecture decisions, security evaluation, and implementation plans

## Run tests

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The in-memory test server can be exercised locally without a Docker daemon:

```sh
python3 -m infrastructure_observer.observer --offline-fixture --host example-host-a
```

The test server listens on loopback and returns synthetic data. No Docker socket is accessed.

## Deployment security

The Docker reader has access only to defined GET routes **at its API boundary**, but a process holding an unrestricted Docker socket still has powerful Docker and host privileges if compromised. The repository does not yet implement an authenticated LAN API, process isolation, production stack configuration, or real-engine compatibility testing. **Do not deploy against a production Docker daemon.** See [engineering planning](planning/README.md) for the safety requirements and remaining work.

This public repository uses synthetic host and project identifiers. Real addresses, permitted project mappings, log data, and credentials must remain outside source control.

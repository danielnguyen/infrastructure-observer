# Milestone B — offline Docker access feasibility and trust review

Status: **Offline prototype only. Not deployable to a real Docker host.**

## Decision

Retain a separate trusted Docker reader behind an unprivileged observer API. The Docker reader can request only three fixed **GET** endpoint shapes from a local Unix socket:

- `GET /v1.41/containers/json?all=1`
- `GET /v1.41/containers/{64-character lowercase hex ID}/json`
- `GET /v1.41/containers/{64-character lowercase hex ID}/logs` with a **fixed** six-parameter schema and bounded values.

The reader never forwards arbitrary caller-supplied Docker routes, methods, query strings, container names, or filesystem paths. It checks exact project membership against freshly inspected labels and the operator's separately verified project allowlist immediately before requesting logs. No Docker archive, exec, filesystem, mutation, network, stats streaming, events, or generic proxy endpoints are supported.

All published identifiers and fixture data are synthetic. Keep real LAN addresses, stack/project allowlists, access credentials and logs out of public Git.

## The essential privilege caveat

**This is NOT a read-only Docker credential.** Whoever compromises the trusted reader while it possesses the normal rootful Docker socket may gain control of Docker/the host. A `:ro` socket bind does not address that risk. The implemented method/path allowlist protects the interface the reader *offers*, not the reader process itself. Do not deploy until the operator explicitly accepts that residual exposure or a stronger enforcement option is demonstrated.

The intended future split is:

`PAB → authenticated TLS observer API (no docker.sock) → local restricted IPC → trusted Docker reader (docker.sock)`.

The implementation in this PR includes **only** the Docker reader library and mocked boundary tests. It does **not** implement IPC, LAN API authentication/TLS, container isolation, Portainer packaging, production credentials, or a live Docker connection. The pre-existing HTTP fixture process still binds **loopback only** with empty fake data.

A single Portainer stack may eventually contain two minimal containers. That deployment design remains gated on independent testing and owner approval. In particular, never directly expose the reader or its Docker socket to the API process, the LAN, ChatGPT, Codex or PAB.

## What the offline tests actually prove

- An artificial Unix-domain HTTP Docker daemon receives only a constructed, permitted GET request; attempts to use disallowed routes never reach it.
- A mocked provider lists running/stopped containers, matches exact 64-hex IDs, and maps Docker's real `Config.Labels` and `NetworkSettings.Ports` *shapes* into allowlisted output fields.
- Requests to fetch logs from non-allowlisted projects never invoke the Docker logs endpoint, including when the caller bypasses the public route handler and calls the provider directly.
- Log-project membership is checked a second time against a fresh inspect response. Mismatches and ambiguous data fail closed.
- Log framing, API path/query restrictions and output caps have tests; unknown secrets in log bodies are **not** guaranteed to be removed.

The tests do **not** prove actual Docker Engine compatibility, socket-bearing process isolation, effective read-only authority after a code compromise, Portainer-to-Compose mapping, TLS/authentication, resistance to all log-secret formats, or production safety.

## Next independent checks (not authorized in this change)

1. Verify actual Docker Engine/API version and the daemon's log-stream format against disposable Linux containers. Adapt API version only after compatibility evidence.
2. Build and test a **separate** Unix-IPC boundary between an unprivileged LAN API and the privileged reader. Prove the API container cannot reach the Docker socket, even if it is fully compromised.
3. Resolve the remaining high-privilege trust question. Alternatives such as host-produced sanitized snapshots may be preferable if the risk of a long-running socket-bearing sidecar is unacceptable; do not silently weaken policy for convenience.
4. Verify Compose-project-to-Portainer-stack identity with owner-supplied evidence. This is a requirement before enabling real logs.
5. Only after the above, explicitly authorize deployment to a single test host and then production through Portainer. No production changes are implied by merging code.

## References

- Docker daemon socket access: https://docs.docker.com/engine/security/protect-access/
- Docker authorization model: https://docs.docker.com/engine/extend/plugins_authorization/
- Docker Engine API version history: https://docs.docker.com/reference/api/engine/version-history/
- OWASP Docker security: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

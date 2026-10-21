# Infrastructure Observer — v1 boundary and offline build brief

Status: **Design only; no deployment or production access authorized**  
Date: 2026-10-21  
Source of runtime inventory: owner-provided `docker inspect` label extracts from both hosts.  
Security stance: read-only *API and model interface*; actual Docker daemon privilege boundary MUST be separately proven before deployment.

## 1. Purpose and non-goals

Make Docker/Portainer observations available to ChatGPT and (when necessary) Codex through PAB, without giving either model shell access, Docker administrative commands, arbitrary filesystem access, or arbitrary network access.

Keep operating cost low: same observer code for two machines; one Portainer stack per host; no new database, polling service, agent framework, event broker, or remediation engine. PAB is already the aggregator. First milestone is an offline testable implementation using fake Docker data.

**Not v1:** automatic vulnerability verdicts, image/host package scanning, active external TLS probing, configuration-file reads, scheduled monitoring or automated remediation. Later vulnerability answers must distinguish confirmed software/version matches, exposure evidence, and gaps. Image tags alone are insufficient for a conclusive CVE result.

## 2. Host inventory and boundaries (public template)

This is an offline policy demonstration using **synthetic hosts and project names**. Production host identifiers, container counts, stack IDs, service names, internal paths, and LAN addresses are deliberately excluded from this public repository.

| Synthetic host | Inventory scope | Detailed logs |
|---|---|---|
| `example-host-a` | All containers | `approved-project` only |
| `example-host-b` | All containers | None initially |

`com.docker.compose.project` is populated in the owner's private discovery samples, but a Compose project label is not verified Portainer stack provenance. One-time mapping verification in Portainer is required before a real deployment. Missing, inconsistent, or ambiguous membership must deny logs. Host-specific production allowlists must be configured outside public source control.

### Explicitly out of scope / forbidden to observer API

- No reads from Portainer filesystem, Docker volumes or host home/config directories.
- No access to `.env`, `stack.env`, credentials, private certificates, Portainer DB, or arbitrary files.
- No raw `docker inspect` or environment maps, arbitrary labels, command arrays, mounts' source paths, Docker APIs, or pass-through HTTP.
- No create/start/stop/restart/kill/exec/update/build/pull/delete/volume/filesystem operations, even when a caller requests them.
- No arbitrary hostnames, ports, URLs, Docker API paths, shell strings, or filesystem paths controlled by a caller.
- No server-initiated network crawling or notifications.

## 3. Minimal API contract (proposed)

All responses include `host`, `observed_at` (UTC), `source` (Docker), and explicit `partial`/`warnings` when data is unavailable. Container IDs are canonicalized to exact matching IDs; no substring matching. The server derives host identity from fixed local configuration, never from client inputs.

- `GET /v1/health` — service readiness only, no sensitive diagnostics.
- `GET /v1/containers` — bounded all-container inventory with ID, name, Compose project, image reference/ID, created time, runtime state, health, published ports and image digest if obtainable safely. Exclude raw commands, environment, labels other than the project identifier, and mounts.
- `GET /v1/containers/{id}` — one sanitized inspect projection of the same approved fields plus restart count, safe health summary, exit code and start/finish times. Must not return `.Config.Env`, `.HostConfig`, complete `.Config.Labels`, `.Mounts`, command arguments or raw inspect output.
- `GET /v1/projects` — project names and container counts, including unlabelled/unknown group clearly marked.
- `GET /v1/projects/{project}/logs?since=<bounded>&limit=<bounded>` — **only** if the project is host-allowlisted **and** current container membership is verified immediately before retrieval. Fetch logs by exact current container IDs after authorization. Clamp to modest duration, timeouts, total characters and per-container lines. No Docker-style raw options or user-supplied filenames.

Logging precautions: treat log entries as untrusted content, including possible prompt injection and secrets. Filter known sensitive patterns and disallow unbounded raw logs; this is best-effort confidentiality protection and MUST NOT be represented as guaranteed removal of unknown secrets. Surface truncation, redaction and failures explicitly. Owner accepts residual sensitivity risk before enabling live log retrieval.

## 4. Docker privilege boundary — explicit design gate

Docker daemon socket access is root-equivalent in common rootful Docker installations. A `:ro` socket mount and 'only use GET' code conventions do **not** revoke daemon administrative capability. Even `GET` families can expose filesystem archives. Therefore:

1. The LAN-facing API process must have **no** direct Docker socket, CLI-to-daemon credential or unrestricted daemon endpoint.
2. A separate, locally reachable **trusted** Docker access boundary must permit only exact, needed Docker request methods and routes; **not** a broad `CONTAINERS=1` GET toggle that also permits `/containers/{id}/archive`.
3. The Docker-access component has elevated trust even when its allowed routes are read-only; its compromise may still have host-level impact. This residual risk must be acknowledged, not described as fully OS-enforced read-only Docker access.
4. Do not alter the Docker daemon or install a Docker authorization plugin as a convenience workaround. If the precise route-enforcement mechanism adds unacceptable complexity, stop at fixture-only implementation and obtain a design decision instead of weakening the boundary.
5. A single *Portainer stack* with two minimal cooperating containers (narrow Docker-access gate and unprivileged API) is acceptable if tests and threat review show that this is the lightest safe implementation. Both share a fixed image/version policy and require no additional database.

Before production deployment, test allowlist vs explicit denial for every HTTP method and route, including path encoding, redirects, URL normalization, API version prefix, repeated parameters and `/containers/{id}/archive`. Deny all unspecified operations. No shell or exec in either service. Set resource limits, no-new-privileges, drop Linux capabilities where feasible, read-only rootfs and restricted network.

## 5. Networking and PAB boundary

- Intended connection: PAB controller on `trusted-pab-host` directly to two fixed observer LAN IPs (IP values not supplied/verified yet). No Tailscale/Cloudflare/public exposure required.
- Authenticate each request; use transport encryption with validated peer identity. Reuse an existing local reverse proxy/certificate arrangement **only if** verified; no unauthenticated HTTP bearer token on the LAN.
- Firewall/host network policy permits inbound observer requests only from the trusted PAB host.
- PAB controller performs fixed-target requests with timeout, output-size cap, deny-redirect, query schemas and no user-controlled URL/port.
- Existing PAB local Codex command sandbox's network-disabled policy remains unchanged. The controller fetches the bounded evidence and hands it to the model; Codex does not call the observer directly.
- Existing PAB repository task APIs are not an implicit diagnostics endpoint. Add separate read-only MCP operation(s) only after the observer's safety contract passes offline tests. Keep pre-existing PAB task semantics and permission contracts untouched.

## 6. Offline milestones

### A — Contract and fixture prototype (first change; entirely offline)

Implement deterministic observer API handlers with an injectable fixture-backed Docker provider. Include synthetic host/project membership test fixtures **without real logs or secrets**. No Docker socket, real endpoint, Portainer API, production paths, deploy instructions that activate services, or PAB changes. Provide a small Dockerfile/Compose *example for offline tests only* if useful.

Tests required:
- Inventory includes stopped and running containers from multiple synthetic projects.
- Only explicit safe fields in inspect; no env, command args, mount paths, secret-bearing labels or raw engine JSON.
- `approved-project` logs allowed on `example-host-a` only; logs denied for `finances`, `media`, `home-devops`, and all projects on `example-host-b`.
- Missing/ambiguous labels deny logs; ensure no partial-match or project-prefix authorization.
- Request paths, project names, IDs and query parameters validated; injection, double-encoding, traversal and overflow rejected.
- Body/line/duration caps, unknown-method denial, no mutating endpoints; observability errors report missing evidence instead of clean health.
- Log content treated as untrusted; known sensitive fixture samples suppressed; failures indicated; unrecognized secrets cannot be guaranteed filtered.
- No network, Docker daemon or filesystem access in test execution.

### B — Docker access adapter and trust review (separate change)

Prototype a route-enforced trusted local Docker access gateway against a disposable Docker daemon/test containers only. Validate route-by-route authority and demonstrate blocked mutation/exfiltration routes. If it cannot be safely constrained without overengineering, stop for a design decision. Do not deploy to either production host.

### C — PAB read-only integration (separate change)

Add a strict-schema MCP read-only operation (e.g. `observe_infrastructure`) in PAB with `host` fixed enum and `operation` fixed enum; pass it through controller-owned fixed-address adapter; preserve tunnel/personal authorization, audit, error reporting, backend separation and existing Codex network-disablement. Exercise with mocked observers. No production configuration change.

### D — Human-controlled staging and production rollout (not yet authorized)

Verify stack identity vs Portainer, local IP reachability/firewall/TLS, observer image provenance and deployment artifact, and then deploy manually through Portainer only following owner approval. Demonstrate no Docker administration, no secret/raw inspect leakage, log authorization and clean removal. First deploy to one server, review, then the second.

## 7. Explicit unresolved items (not blockers for Milestone A)

1. Actual LAN IPs, transport identity and firewall rule validation.
2. Exact Portainer stack names/project correspondences; owner to confirm with UI once.
3. Choice and demonstrated trust characteristics of Docker access gate.
4. Whether the owner permits residual secret-exposure risk from `approved-project` log lines, notwithstanding bounded filtering.
5. Software/image vulnerability matching, host package checks and live TLS endpoint checks belong to later scope, not initial inventory/log prototype.

## 8. Keep-it-small acceptance

A single reusable observer image/config schema for both hosts. At most one Portainer stack per host, even if two processes/containers are technically necessary. No persistence or broker. No background polling. No deployment tooling with model access. No additions to CCP. No expanded PAB execution networking. An unauthorized/unavailable observation must never become a security assurance.

### Sources

- Docker authorization default is all-or-nothing: https://docs.docker.com/engine/extend/plugins_authorization/
- Docker daemon/socket security: https://docs.docker.com/engine/security/protect-access/
- Docker Compose project label: https://docs.docker.com/compose/intro/compose-application-model/
- Docker GET archive endpoint: https://docs.docker.com/reference/api/engine/version/v1.40/
- PAB source and security contract (checked 2026-10-21): https://github.com/danielnguyen/personal-agents-bridge/blob/main/server.mjs and https://github.com/danielnguyen/personal-agents-bridge/blob/main/SECURITY.md

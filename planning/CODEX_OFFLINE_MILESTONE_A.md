# Codex task — infrastructure-observer MVP, offline contract only

Implement **Milestone A only** of `planning/BOUNDARY_AND_OFFLINE_BUILD.md`.

## Scope

Build a small deterministic API implementation for observer inventory, container summaries, project listing and strictly approved project logs using a fixture-backed Docker provider, with thorough unit tests. **No actual connection to Docker, Portainer, either user's production host, a public network, or PAB**. Use the simplest maintainable stack (small standard-library server where possible), no database, queues, AI framework, polling daemon or automatic remediation. Production adapter, deployment and PAB integration are separate future milestones.

Implement the exact schema, allowlist and denial behavior in the spec. Have the API consume injected provider outputs, never raw caller-configurable Docker requests. Fixed two host identities; `example-host-a` initially has only `approved-project` in the log allowlist; `example-host-b` has no log permissions. Preserve denial on missing/ambiguous memberships. Mark synthetic fixtures and simulated results clearly so they are not mistaken for real security evidence.

## Requirements

1. No arbitrary shell/process/network/filesystem execution or Docker socket usage.
2. No raw inspect output; strict projection of safe fields, with tests for environmental secrets, privileged configs, mount source paths, commands and dangerous labels.
3. Project-scoped logs must verify exact current membership at time of collection, not just trust a supplied name.
4. Reject unauthorized project logs, injection/traversal in inputs, unknown routes/methods, unlimited queries, malformed inputs and excessive responses.
5. Handle stopped containers, missing health, partial provider errors and stale data explicitly.
6. Bound log time window, output bytes, line counts and provider runtime; sensitive log-line suppression is best effort, not a confidentiality guarantee.
7. Tests must verify all above against synthetic fixtures; tests should not call Docker or either host.
8. Include a short README with run/test instructions and a warning that **the fixture prototype is not safe to deploy or connect to the actual Docker daemon**.

## Exit conditions

Run tests and a lightweight static check, summarize test count and code changes. Do not change any live infrastructure, PAB, Docker daemon configuration or Portainer stack. Do not create a PR, push or deploy unless separately authorized. Any conflict between functional scope and enforceable read-only Docker access must stop with a clear design note rather than weakening the security boundary.

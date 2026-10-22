# Observation API hardening and packaged boundary tests

Scope: deterministic observer and disposable Docker tests. This document does not authorize access to production Docker hosts.

## Request limiting

The network-facing API applies one process-wide, constant-memory token bucket **after authentication and path validation** and before forwarding to the reader: capacity 24; refill one observation per second. Excess authorized requests receive HTTP 429 with `RATE_LIMIT` and `partial: true`; they never reach the Docker reader. The limiter deliberately has no per-IP state, which would otherwise permit unbounded memory growth from source-address churn. This is a workload safeguard, not a substitute for ingress firewalling or upstream network rate controls.

Unauthorized requests do not consume observation tokens. The bound is local to one API process; running replicas would multiply aggregate capacity. A process restart resets the bucket. The caller should avoid immediate aggressive retries.

## Packaged-container security checks

The disposable Compose smoke test now executes adversarial probes *inside the running containers*, rather than assuming Compose metadata constitutes an enforceable permission:

- The API runs as UID 65532, lacks the Docker socket and cannot connect to it.
- The API can observe the IPC socket but cannot unlink it or add files to the read-only IPC mount.
- Reader has a read-only root filesystem and cannot establish outbound TCP connectivity with `network_mode: none`.
- Docker reader restart after an abrupt PID 1 termination recreates its shared IPC endpoint and restores API health.
- Existing tests continue to cover bearer authentication, TLS trust, read-only paths, project-scoped logs and safe metadata projection.

This is a CI-only destructive test against a disposable reader service. It must **never** be executed against the production hosts.

## Residual authority and rollout gate

The reader's access to an unrestricted **rootful Docker socket is still administrative authority** if the reader process is compromised. No API-level route list or read-only socket bind makes the daemon credential read-only. This is an explicit unresolved security decision. Do not deploy to production without an accepted risk decision or a different collection mechanism.

Further host-specific requirements: approve and verify stack-to-Compose project mapping; validate Docker/Portainer versions; constrain LAN ingress to the PAB host; provision credentials/certificate privately and test rotation; restrict reader resources and Docker socket exposure; verify all observations are reported with timestamps and partial/inconclusive state. Integration with PAB remains a separate change.

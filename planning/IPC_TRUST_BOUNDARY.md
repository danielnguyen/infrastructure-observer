# Local reader / LAN API trust boundary

Status: implementation validated against synthetic fixtures and a disposable local Unix socket, **not production-authorized**.

## Decision

Run one codebase in two distinct process/container roles on each host:

1. `gateway`: the trusted reader; has the local Docker socket and a predefined list/inspect/project-log contract. Exposes only a private Unix-socket observation API, not TCP.
2. `api`: the unprivileged network-facing process; has an authenticated TLS listener and a client for the **separate observer IPC socket**. It never receives or mounts Docker's administration socket.

Only the reader needs Docker privileges. The LAN interface rejects unauthenticated requests before contacting its local gateway, restricts operations to fixed GET observation routes, caps response sizes and concurrent requests, and never forwards arbitrary Docker URLs.

Permissions are supplied at startup. `gateway --log-project ...` sets the trusted project's allowlist. Missing permission grants no log access. The observer also independently verifies that the requested project's containers currently belong to that Compose project before requesting logs. This label is not yet independently proven equivalent to a Portainer stack identity.

The Unix-socket parent directory must be owned by the gateway process with group **read/execute but not write** and no access for other users. Its socket is created mode 0660, with the gateway and API processes sharing a deliberately restricted group. The API process must not have permissions to the Docker socket or the gateway's runtime state. A group-writable IPC directory would permit endpoint substitution and must not be used.

## What tests establish

- An authenticated request reaches the local gateway and returns a projected inventory, not raw inspect fields.
- Missing/incorrect API bearer token is denied before gateway access.
- Disallowed paths and HTTP mutation methods do not reach the gateway.
- Unauthorized project logs are denied, even if the gateway is contacted directly.
- Gateway failure surfaces a partial/unavailable result.
- The IPC socket is access-controlled by mode; public directories and existing socket paths fail at creation.
- A TLS API listener successfully handles HTTPS and rejects plaintext HTTP in a local synthetic test.
- The existing fake-Docker Unix-domain socket tests remain green.

## Important unproven properties and blockers

- **Docker socket possession remains effectively host-administrative authority.** No kernel or Docker-daemon authorization rule restricts a compromised gateway to read-only requests. The separation **limits what a compromised API process can request**, but not what a compromised socket-holding gateway process can do. This risk requires an explicit acceptance decision or a stronger collection mechanism before connecting to production.
- The unit tests run services in one host user context. Container UID/GID isolation, the absence of the Docker socket from the API process, and permissions against a genuinely compromised API must be independently validated on disposable Linux/Docker hosts.
- The TLS test uses an ephemeral self-signed certificate. Real certificate trust, key provisioning/rotation and private-LAN firewall binding are unverified; no TLS keys or credentials belong in Git.
- Docker/Portainer stack identification, host Docker API compatibility, safe handling of malicious log contents, deployment manifests and PAB integration have not been validated or implemented.
- Health checks report IPC gateway responsiveness only; they are not a Docker availability or vulnerability verdict.
- The implementation does not yet limit how frequently a single authenticated client can ask for expensive full inventories. Concurrent requests have a bound, but network-level rate-limiting still requires a deployment decision.

## Required disposable deployment verification

Run the reader with the Docker socket only inside its isolated service and the API under a distinct unprivileged identity. Prove the API can retrieve approved synthetic observations, cannot open or connect to Docker's socket by any path, cannot replace the IPC socket, cannot obtain raw inspect JSON, and cannot invoke mutations even with a compromised request client. Validate certificates and local firewall restrictions. Fail closed if these checks do not pass.

This is a design and testing gate, not deployment authorization.

References: [Docker daemon protection](https://docs.docker.com/engine/security/protect-access/), [Docker Engine authorization](https://docs.docker.com/engine/extend/plugins_authorization).

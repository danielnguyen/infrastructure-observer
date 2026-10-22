# Container packaging and isolation acceptance

The deployment candidate uses one Docker image in two roles inside one Portainer-compatible Compose stack. No service or artifact is authorized for production installation by this document.

## Authority model

- `reader` has a rootful Docker socket and is therefore highly trusted. This is not an OS-enforced read-only Docker identity; its behavior is constrained by application routes only. Do not claim that a compromised reader is read-only.
- `reader` has no network namespace connectivity beyond its loopback, a read-only container filesystem, all Linux capabilities dropped, and no-new-privileges. It can still issue powerful requests to Docker through the mounted socket.
- `api` is UID/GID 65532, has no Docker socket mount, a read-only filesystem, all capabilities dropped, no-new-privileges, and only the Unix IPC socket (mounted read-only) and a dedicated external read-only certificate/token directory.
- `ipc_init.py` prepares the reader-owned shared directory with mode 2750 and group 65532, only if it is an empty root-owned directory or contains a verifiably stale reader socket. It rejects unexpected entries and active readers.
- An unauthenticated health endpoint is not offered. A caller must use HTTPS and the bearer credential. A source-IP firewall must separately enforce PAB-only access.

## Tests required before rollout

1. Disposable `docker compose config`, image build, stack startup and teardown.
2. API UID 65532, read-only root filesystem, no Docker socket or Docker admin access.
3. Reader no TCP network; Docker read-only operations and stack-permission enforcement; confirm forbidden HTTP methods/paths.
4. Shared socket UID/GID/mode. Unauthorized processes cannot connect; startup fails if socket state is ambiguous.
5. TLS certificate verification, missing/malformed credentials, request rate/concurrency behavior, and failure isolation.
6. Verify Portainer version/Compose parsing on both target hosts from operator-supplied read-only evidence; verify Compose project-to-Portainer-stack mapping before enabling production logs.
7. Residual rootful Docker socket risk requires explicit acceptance or a different collector design.

## Delivery progression

Keep container build artifacts and synthetic tests in GitHub Actions. Do not publish an image as "production-ready" or deploy without fulfilling the security gates above. Real host IPs, secrets, and inventory are not included in this public repository.

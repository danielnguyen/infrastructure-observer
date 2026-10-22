# Container packaging

The same image runs a Docker reader (`reader`) and an HTTPS observation API (`api`). The reader has no container networking; the API has no Docker socket. The only shared surface is a group-restricted Unix socket in a dedicated Docker volume.

This Compose file is a deployment *candidate*, not authorization to install on an operational server. See `../planning/CONTAINER_PACKAGING.md` for the verification gates and Docker privilege limitation.

For validation in a disposable environment, build a local image and set `OBSERVER_IMAGE` to its tag. Other required values are `OBSERVER_HOST` (non-sensitive identity), `OBSERVER_LOG_PROJECTS` (comma-separated verified project allowlist; empty means none), `OBSERVER_BIND_IP` (explicit private interface or loopback address), and `OBSERVER_CREDENTIALS_DIR` (absolute path to a directory containing `cert.pem`, `key.pem` and `token`). Do not commit these real settings.

The credentials directory must be inaccessible to unrelated users and readable by UID 65532 inside the API container. Store the token in a regular mode-0600 file and use a strong random value of at least 32 characters. Provision a certificate whose SAN matches the name/address PAB uses, and configure PAB to verify the certificate. Secrets are never passed through container environment variables.

Do not treat `:ro` on the Docker socket mount as a Docker API permission restriction. A compromised `reader` process may still control Docker/the host. The API's default bridge networking does not itself impose a source-IP firewall; restrict caller reachability to PAB at the host/network layer before production use.

# Offline infrastructure observer proof of concept

**Not production-ready. Do not point this code at either real Docker host.**

The API in `observer.py` still runs only against explicitly supplied synthetic fixtures. The offline executable binds `127.0.0.1`, not a LAN interface.

`docker_gateway.py` is a *library only* for evaluating narrow Docker reads. It can contact a Unix Docker HTTP socket if another application explicitly instantiates it, which is prohibited against production at this stage. It deliberately contains no command-line entry point, daemon, listener or deployment instructions.

Test without Docker or any network daemon:

```bash
cd offline-prototype
python3 -m unittest discover -s . -p 'test_*.py' -v
```

Tests use JSON fixtures and a disposable fake Unix-domain HTTP server. The fake daemon is not Docker Engine and does not establish live-engine compatibility.

The reader's allowed Docker access is limited to fixed list/inspect/log GET endpoint shapes. Inspect data stays inside the trusted reader and is projected onto an explicit safe field schema before becoming a response. Log reads are restricted to operator-verified Compose projects and recheck membership at the time of retrieval. Unknown log secrets may still escape heuristic redaction.

For the security analysis, especially the root-equivalent **Docker socket compromise risk** and deployment blockers, see `../MILESTONE_B_TRUST_REVIEW.md`.

# Offline infrastructure observer protocol prototype

**Not deployable. No Docker, Portainer, PAB, SSH or production connectivity.** This is a test-only protocol boundary demo implemented using Python standard library. It has no Docker socket integration, TLS, authentication or production-ready Docker privilege controls. It must not be exposed beyond local loopback and must never be used with production data.

```bash
python3 -m unittest discover -s . -p 'test_*.py' -v
python3 observer.py --offline-fixture --host example-host-a --port 8765
# In another terminal: curl http://127.0.0.1:8765/v1/containers
```

The CLI uses an *empty synthetic fixture* and deliberately returns no actual containers. Unit tests inject synthetic fixture records only. No background polling, DB, additional dependencies, or autonomous capabilities.

This first slice tests proposed routes, host/project authorization, narrow field projections, query bounds and error handling. Its redaction is heuristic, so enabling real logs later requires a separate confidentiality decision. The future Docker gate, authentication and TLS, and PAB integration are separate milestones described in `../BOUNDARY_AND_OFFLINE_BUILD.md`.

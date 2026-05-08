# MalSight

Phase 6: project README — scaffold only.

AI-powered malware analyzer with a Gemini 1.5 Pro agent brain.
One-command setup, API key configuration guide, and demo instructions to be added here.

## Sandbox image dependencies

The `malsight-sandbox` Docker image must have **7zip** installed for zip-file
extraction inside the gVisor sandbox:

```dockerfile
RUN apt-get update && apt-get install -y 7zip p7zip-full
```

This is required to support `.zip` uploads (e.g. MalwareBazaar samples packed
with the standard `infected` password). The extraction happens entirely inside
the container — the host filesystem never sees the malware binary.

from __future__ import annotations
import os
import functools


@functools.lru_cache(maxsize=None)
def get_secret(name: str) -> str:
    """Return the named secret, trying env vars first then GCP Secret Manager."""
    val = os.getenv(name)
    if val:
        return val
    project = os.getenv("GCP_PROJECT")
    if project:
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            path = f"projects/{project}/secrets/{name}/versions/latest"
            return client.access_secret_version(name=path).payload.data.decode()
        except Exception as e:
            raise RuntimeError(
                f"Secret {name} not found in env or Secret Manager: {e}"
            )
    raise RuntimeError(
        f"Secret {name} not found in env or Secret Manager: GCP_PROJECT not set"
    )


GEMINI_API_KEY     = lambda: get_secret("GEMINI_API_KEY")
DATABASE_URL       = lambda: get_secret("DATABASE_URL")
REDIS_URL          = lambda: get_secret("REDIS_URL")
VIRUSTOTAL_API_KEY = lambda: get_secret("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY  = lambda: get_secret("ABUSEIPDB_API_KEY")
MALSIGHT_API_KEYS  = lambda: get_secret("MALSIGHT_API_KEYS").split(",")
SANDBOX_IMAGE      = lambda: get_secret("SANDBOX_IMAGE")
GCP_PROJECT        = lambda: os.getenv("GCP_PROJECT", "")
GKE_CLUSTER        = lambda: os.getenv("GKE_CLUSTER", "")
GKE_ZONE           = lambda: os.getenv("GKE_ZONE", "")

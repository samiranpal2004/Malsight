"""mail_processor package — re-exports process_email so RQ can resolve
   `mail_processor.process_email` whether the worker runs from the project
   root (package layout) or inside the Docker image (flat layout)."""
try:
    from mail_processor.mail_processor import process_email  # noqa: F401
except ImportError:
    # Inside the Docker image, mail_processor.py and db.py sit flat in /app
    # and `mail_processor` is the module itself, not a package — nothing to do.
    pass

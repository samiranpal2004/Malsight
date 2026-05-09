"""Send a test email to the MalSight SMTP server for demo/testing."""
import smtplib
import sys
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# ── Config ────────────────────────────────────────────────────────────────────
SMTP_HOST   = "127.0.0.1"
SMTP_PORT   = 2525
TO_ADDR     = sys.argv[1] if len(sys.argv) > 1 else "analyst@company.com"
FROM_ADDR   = "attacker@evil.com"
SUBJECT     = "Q2 Financial Report — Please Review"
BODY        = "Hi,\n\nPlease find the Q2 financial report attached for your review.\n\nRegards"

# Attachments to include — pass paths as extra args, e.g.:
#   python send_test_email.py analyst@company.com path/to/file.exe
ATTACH_PATHS = sys.argv[2:] if len(sys.argv) > 2 else []

# ── Build message ─────────────────────────────────────────────────────────────
msg = MIMEMultipart()
msg["From"]    = f"CFO Office <{FROM_ADDR}>"
msg["To"]      = TO_ADDR
msg["Subject"] = SUBJECT
msg.attach(MIMEText(BODY, "plain"))

for path in ATTACH_PATHS:
    filename = os.path.basename(path)
    with open(path, "rb") as fh:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(fh.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
    msg.attach(part)
    print(f"  Attached: {filename}")

# ── Send ──────────────────────────────────────────────────────────────────────
print(f"Sending to {TO_ADDR} via {SMTP_HOST}:{SMTP_PORT} ...")
with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
    s.sendmail(FROM_ADDR, [TO_ADDR], msg.as_bytes())

print("Done! Open the webmail inbox and enter:", TO_ADDR)
print(f"  http://localhost:5173/mail  (or http://localhost:3000/mail if using Docker)")

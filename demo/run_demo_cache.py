# Phase 6: Pre-caches demo reports in PostgreSQL so no live APIs are called during the pitch.
# Scaffold only — implement in Phase 6.
#
# Runs analysis on four demo samples (stored in demo/samples/):
#   1. benign_script.py    — fast-track benign demo (2-3 tool calls, ~8 s)
#   2. known_hash.exe      — known-malicious hash demo (1 tool call, ~3 s)
#   3. upx_trojan.exe      — full UPX-packed agent investigation (~45 s)
#   4. pdf_with_js.pdf     — PDF with embedded JavaScript (~40 s)
#
# Usage: python demo/run_demo_cache.py
# Requires: Redis + PostgreSQL running (docker-compose up)

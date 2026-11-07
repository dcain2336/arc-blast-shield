#!/bin/sh
# Start ARC Blast Shield locally.
# Env: VULTR_API_KEY (optional — without it the deterministic local-fallback
# analyst runs and the UI labels it), VULTR_MODEL (default kimi-k2-instruct),
# PORT (default 8080).
cd "$(dirname "$0")"
export BLASTSHIELD_PY="$PWD/.venv/bin/python"
exec "$PWD/.venv/bin/python" server.py

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install -r requirements.txt

if [ ! -f "config.json" ]; then
  cp config.local-cmux.example.json config.json
fi

exec .venv/bin/python monitor_server.py --host 127.0.0.1 --port "${PORT:-8787}"

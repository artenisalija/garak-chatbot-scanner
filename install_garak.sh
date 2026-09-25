#!/usr/bin/env bash
# Installs NVIDIA garak into ./.venv (Python 3.12) and verifies it works.
# Safe to re-run: it reuses the venv and just upgrades garak.
#
# Usage:  bash install_garak.sh
set -euo pipefail

cd "$(dirname "$0")"

# 1. uv: fast Python/venv manager. Garak needs Python 3.10-3.12, and newer
#    system Pythons (e.g. 3.14) are not supported, so uv fetches 3.12 for us.
if ! command -v uv >/dev/null 2>&1; then
  echo ">> uv not found, installing it (https://astral.sh/uv)"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# 2. Virtual environment
if [ ! -x .venv/bin/python ]; then
  echo ">> creating .venv with Python 3.12"
  uv venv --python 3.12 .venv
else
  echo ">> reusing existing .venv"
fi

# 3. Garak
echo ">> installing / upgrading garak"
uv pip install --python .venv/bin/python -U garak

# 4. Verify: version, then a dry run that needs no API key or network
echo ">> verifying"
.venv/bin/garak --version
.venv/bin/garak --target_type test.Blank --spec probes.test.Test 2>&1 \
  | sed 's/\x1b\[[0-9;]*m//g' | tr '\r' '\n' | grep -E "PASS|FAIL|complete" || true

cat <<'EOF'

garak is installed. It is a command-line tool, not a server, so there is no
localhost page to open. To use it:

  cd "$(dirname "$0")"        # this folder
  source .venv/bin/activate

  # explore
  garak --list_probes
  garak --list_generators

  # scan a Groq-hosted model (key goes in your terminal only, never in a file)
  export GROQ_API_KEY="gsk_..."
  garak --target_type groq                                  # lists available models
  garak -t groq -n llama-3.1-8b-instant -g 1 \
        --spec probes.promptinject.HijackHateHumans

  # look at what worked
  python3 show_hits.py --summary
  python3 show_hits.py -n 5

Reports are written to ~/.local/share/garak/garak_runs/
EOF

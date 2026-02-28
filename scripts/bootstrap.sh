#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"
ENV_EXAMPLE="$PROJECT_DIR/.env.example"

# ── helpers ──────────────────────────────────────────────────────────────────
rand_hex() { openssl rand -hex "$1" 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex($1))"; }

info()  { printf '  \033[1;34m→\033[0m %s\n' "$*"; }
ok()    { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[1;33m!\033[0m %s\n' "$*"; }

# ── pre-flight ───────────────────────────────────────────────────────────────
if [ -f "$ENV_FILE" ]; then
  warn ".env already exists. Remove it first to re-bootstrap, or edit it directly."
  exit 1
fi

if [ ! -f "$ENV_EXAMPLE" ]; then
  echo "ERROR: $ENV_EXAMPLE not found." >&2
  exit 1
fi

# ── create .env from template ────────────────────────────────────────────────
cp "$ENV_EXAMPLE" "$ENV_FILE"
ok "Created .env from .env.example"

# ── generate gateway token ──────────────────────────────────────────────────
TOKEN="$(rand_hex 32)"
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' "s|^OPENCLAW_GATEWAY_TOKEN=.*|OPENCLAW_GATEWAY_TOKEN=${TOKEN}|" "$ENV_FILE"
else
  sed -i "s|^OPENCLAW_GATEWAY_TOKEN=.*|OPENCLAW_GATEWAY_TOKEN=${TOKEN}|" "$ENV_FILE"
fi
ok "Generated random gateway token"

# ── generate SearXNG secret key ───────────────────────────────────────────
SEARXNG_SETTINGS="$PROJECT_DIR/searxng/settings.yml"
if [ -f "$SEARXNG_SETTINGS" ]; then
  SEARXNG_KEY="$(rand_hex 32)"
  if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "s|REPLACE_ME_ON_BOOTSTRAP|${SEARXNG_KEY}|" "$SEARXNG_SETTINGS"
  else
    sed -i "s|REPLACE_ME_ON_BOOTSTRAP|${SEARXNG_KEY}|" "$SEARXNG_SETTINGS"
  fi
  ok "Generated SearXNG secret key"
fi

# ── set .env file permissions ─────────────────────────────────────────────
chmod 600 "$ENV_FILE"
ok "Set .env permissions to 600 (owner-only)"

# ── detect openclaw source dir ──────────────────────────────────────────────
OPENCLAW_DEFAULT="$HOME/Developer/openclaw"
if [ -d "$OPENCLAW_DEFAULT" ]; then
  OPENCLAW_SRC="$OPENCLAW_DEFAULT"
elif [ -d "$(dirname "$PROJECT_DIR")/openclaw" ]; then
  OPENCLAW_SRC="$(cd "$(dirname "$PROJECT_DIR")/openclaw" && pwd)"
else
  OPENCLAW_SRC=""
fi

if [ -n "$OPENCLAW_SRC" ]; then
  if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' "s|^OPENCLAW_SRC_DIR=.*|OPENCLAW_SRC_DIR=${OPENCLAW_SRC}|" "$ENV_FILE"
  else
    sed -i "s|^OPENCLAW_SRC_DIR=.*|OPENCLAW_SRC_DIR=${OPENCLAW_SRC}|" "$ENV_FILE"
  fi
  ok "Auto-detected openclaw source: $OPENCLAW_SRC"
else
  warn "Could not auto-detect openclaw repo. Set OPENCLAW_SRC_DIR in .env manually."
fi

# ── summary ──────────────────────────────────────────────────────────────────
echo ""
echo "┌──────────────────────────────────────────────────────┐"
echo "│  Bootstrap complete                                  │"
echo "├──────────────────────────────────────────────────────┤"
echo "│                                                      │"
echo "│  Next steps:                                         │"
echo "│                                                      │"
echo "│  1. Edit .env and add at least one LLM API key:      │"
echo "│       ANTHROPIC_API_KEY=sk-ant-...                   │"
echo "│     or                                               │"
echo "│       OPENAI_API_KEY=sk-...                          │"
echo "│                                                      │"
echo "│  2. Verify OPENCLAW_SRC_DIR points to the            │"
echo "│     openclaw git checkout.                           │"
echo "│                                                      │"
echo "│  3. Start:                                           │"
echo "│       ./scripts/up.sh                                │"
echo "│                                                      │"
echo "│  4. Open http://127.0.0.1:3210 in your browser.      │"
echo "│                                                      │"
echo "└──────────────────────────────────────────────────────┘"

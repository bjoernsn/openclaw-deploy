#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

if [ ! -f .env ]; then
  echo "ERROR: .env not found. Run ./scripts/bootstrap.sh first." >&2
  exit 1
fi

echo "Building and starting OpenClaw..."
docker compose up --build -d

echo ""
echo "Waiting for health check..."
sleep 5

if docker compose ps --format json 2>/dev/null | grep -q '"healthy"'; then
  echo "OpenClaw is running at http://127.0.0.1:$(grep -oP 'OPENCLAW_HOST_PORT=\K[0-9]+' .env 2>/dev/null || echo 3210)"
else
  echo "Container started. Checking status..."
  docker compose ps
  echo ""
  echo "View logs: docker compose -f $PROJECT_DIR/docker-compose.yml logs -f"
fi

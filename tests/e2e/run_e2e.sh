#!/usr/bin/env bash
# Spin up disposable Postgres + Redis, migrate, run the end-to-end job test, tear down.
# Usage: tests/e2e/run_e2e.sh   (requires docker and the .venv with nautobot installed)
set -euo pipefail
cd "$(dirname "$0")/../.."
export NB_E2E_PG_PORT="${NB_E2E_PG_PORT:-55433}"
export NB_E2E_REDIS_PORT="${NB_E2E_REDIS_PORT:-56380}"
export NAUTOBOT_ROOT="${NAUTOBOT_ROOT:-$(mktemp -d)}"
export DJANGO_SETTINGS_MODULE=nautobot_config_e2e
export PYTHONPATH="$PWD/tests/e2e:${PYTHONPATH:-}"
export NAUTOBOT_E2E=1
PY="${PYTHON:-.venv/bin/python}"

cleanup() { docker rm -f nbfix-e2e-pg nbfix-e2e-redis >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name nbfix-e2e-pg -e POSTGRES_USER=nautobot -e POSTGRES_PASSWORD=nautobot -e POSTGRES_DB=nautobot \
  -p "127.0.0.1:${NB_E2E_PG_PORT}:5432" postgres:15-alpine >/dev/null
docker run -d --name nbfix-e2e-redis -p "127.0.0.1:${NB_E2E_REDIS_PORT}:6379" redis:7-alpine >/dev/null
for _ in $(seq 1 60); do docker exec nbfix-e2e-pg pg_isready -U nautobot >/dev/null 2>&1 && break; sleep 1; done
echo ">> migrating (first run takes a few minutes)"
"$PY" -m django migrate --no-input >/dev/null
echo ">> running end-to-end tests"
"$PY" -m pytest -q tests/test_job_e2e.py "$@"

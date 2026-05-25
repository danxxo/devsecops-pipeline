#!/usr/bin/env bash
# Локальный DAST: поднимает devsecops-стек (api + opensearch),
# гоняет ZAP API scan, складывает отчёт в pipeline/_reports/zap.json,
# гарантированно сносит стек по завершении.
#
# Запуск из корня репозитория:
#   ./pipeline/dast/run.sh
#
# Зависит от:
#   - docker compose
#   - локально собранный образ log-api:devsecops-local
#     (./pipeline/build-and-scan/run.sh build)
#
# ZAP API scan — активный скан по OpenAPI-спеке (явные эндпоинты + active
# scanner: SQLi, XSS, command/SSTI/SSRF/XXE injection). Длится 5-15 минут.
# Стенд эфемерный, после прогона компоуз сносится.
# FAIL/WARN/IGNORE правила в zap-baseline.conf.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORTS_DIR="$REPO_ROOT/pipeline/_reports"
COMPOSE="$SCRIPT_DIR/docker-compose.devsecops.yml"
NETWORK="devsecops_default"

mkdir -p "$REPORTS_DIR"

cleanup() {
  echo "==> tearing down stack"
  docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> docker compose up"
docker compose -f "$COMPOSE" up -d

echo "==> waiting for api to respond on /_ping"
for i in $(seq 1 60); do
  if curl -sf http://localhost:9100/_ping >/dev/null 2>&1; then
    echo "    api ready"
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    echo "    timeout waiting for api" >&2
    docker compose -f "$COMPOSE" logs api | tail -30
    exit 1
  fi
done

echo "==> ZAP API scan (active)"
# ZAP пишет отчёт во внутренний /zap/wrk; его монтируем как _reports.
# Спеку и conf-файл тоже копируем туда чтобы были доступны по короткому имени.
cp "$SCRIPT_DIR/zap-baseline.conf" "$REPORTS_DIR/zap-baseline.conf"
cp "$SCRIPT_DIR/openapi.yml" "$REPORTS_DIR/openapi.yml"
docker run --rm \
  --network="$NETWORK" \
  -v "$REPORTS_DIR:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
    -t /zap/wrk/openapi.yml \
    -f openapi \
    -J zap.json \
    -c zap-baseline.conf \
  || true

# prettify
if [ -s "$REPORTS_DIR/zap.json" ]; then
  python3 -m json.tool --indent 2 "$REPORTS_DIR/zap.json" \
    > "$REPORTS_DIR/zap.json.tmp" && mv "$REPORTS_DIR/zap.json.tmp" "$REPORTS_DIR/zap.json"
fi
rm -f "$REPORTS_DIR/zap-baseline.conf" "$REPORTS_DIR/openapi.yml"

echo
echo "Report → $REPORTS_DIR/zap.json"

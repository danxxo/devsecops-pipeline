#!/usr/bin/env bash
# Локальная сборка образа и скан Trivy.
# Запуск из корня репозитория:
#
#   ./pipeline/build-and-scan/run.sh           # build + trivy
#   ./pipeline/build-and-scan/run.sh build     # только сборка
#   ./pipeline/build-and-scan/run.sh trivy     # только скан (образ уже должен быть)
#
# Зависит от docker. Тэг образа фиксированный:
#   log-api:devsecops-local

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORTS_DIR="$REPO_ROOT/pipeline/_reports"
IMAGE="log-api:devsecops-local"

mkdir -p "$REPORTS_DIR"

run_build() {
  echo "==> docker build ($IMAGE)"
  cd "$REPO_ROOT"
  DOCKER_BUILDKIT=1 docker build -t "$IMAGE" .
}

run_trivy() {
  echo "==> trivy image $IMAGE"
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$REPORTS_DIR:/reports" \
    aquasec/trivy:latest image \
      --scanners vuln,secret,misconfig \
      --severity CRITICAL,HIGH,MEDIUM,LOW \
      --format json --output /reports/trivy.json \
      --quiet \
      "$IMAGE" || true
  # JSON от trivy уже минифицирован — преттифай для глаз.
  if [ -s "$REPORTS_DIR/trivy.json" ]; then
    python3 -m json.tool --indent 2 "$REPORTS_DIR/trivy.json" \
      > "$REPORTS_DIR/trivy.json.tmp" && mv "$REPORTS_DIR/trivy.json.tmp" "$REPORTS_DIR/trivy.json"
  fi
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy:latest image \
      --scanners vuln,secret,misconfig \
      --severity CRITICAL,HIGH,MEDIUM,LOW \
      --quiet \
      "$IMAGE" 2>&1 | tail -30 || true
}

target="${1:-all}"
case "$target" in
  all)   run_build; run_trivy ;;
  build) run_build ;;
  trivy) run_trivy ;;
  *) echo "unknown target: $target (expected: all|build|trivy)" >&2; exit 2 ;;
esac

echo
echo "Reports → $REPORTS_DIR"
ls -la "$REPORTS_DIR"

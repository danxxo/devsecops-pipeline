#!/usr/bin/env bash
# Локальный прогон SCA-сканера (govulncheck).
# Запуск из корня репозитория: ./pipeline/sca/run.sh
#
# Зависит от:
#   go install golang.org/x/vuln/cmd/govulncheck@latest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORTS_DIR="$REPO_ROOT/pipeline/_reports"

mkdir -p "$REPORTS_DIR"

run_govulncheck() {
  echo "==> govulncheck"
  if ! command -v govulncheck >/dev/null; then
    echo "govulncheck не найден. Установка: go install golang.org/x/vuln/cmd/govulncheck@latest" >&2
    return 1
  fi
  cd "$REPO_ROOT"
  # NDJSON-формат: набор объектов через \n. Не пытаемся prettify —
  # формат рассчитан на стриминг, merge_reports.py будет читать построчно.
  govulncheck -format json ./... > "$REPORTS_DIR/govulncheck.json" 2>/dev/null || true
  govulncheck ./... 2>&1 | tail -30 || true
}

target="${1:-all}"
case "$target" in
  all|govulncheck) run_govulncheck ;;
  *) echo "unknown target: $target (expected: all|govulncheck)" >&2; exit 2 ;;
esac

echo
echo "Reports → $REPORTS_DIR"
ls -la "$REPORTS_DIR"

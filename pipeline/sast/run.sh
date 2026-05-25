#!/usr/bin/env bash
# Локальный прогон SAST-сканеров. Выводит результат в терминал, JSON-отчёты
# складывает в pipeline/_reports/. Запуск из корня репозитория:
#
#   ./pipeline/sast/run.sh           # все сканеры
#   ./pipeline/sast/run.sh semgrep   # только semgrep
#
# Зависит от docker (тянет образы инструментов на лету, кэш на машине).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORTS_DIR="$REPO_ROOT/pipeline/_reports"

mkdir -p "$REPORTS_DIR"

# Преобразует JSON-файл в читаемый вид с отступами (in-place).
prettify() {
  local f="$1"
  [ -s "$f" ] || return 0
  python3 -m json.tool --indent 2 "$f" > "$f.tmp" && mv "$f.tmp" "$f"
}

run_semgrep() {
  echo "==> semgrep"
  # Сканим только Go-исходники (cmd/, internal/). Dockerfile/compose/yaml
  # уйдут под Checkov на следующем шаге.
  local targets=(cmd internal)
  local common_args=(
    --config p/golang
    --config p/secrets
    --config pipeline/sast/semgrep-rules.yml
    --config pipeline/sast/external/dgryski/
    --metrics=off
  )
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/src" \
    -w /src \
    returntocorp/semgrep:latest \
    semgrep "${common_args[@]}" \
      --json --output /src/pipeline/_reports/semgrep.json \
      "${targets[@]}" \
      || true
  prettify "$REPORTS_DIR/semgrep.json"
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/src" \
    -w /src \
    returntocorp/semgrep:latest \
    semgrep "${common_args[@]}" "${targets[@]}" \
      || true
}

run_gosec() {
  echo "==> gosec"
  if ! command -v gosec >/dev/null; then
    echo "gosec не найден. Установка: go install github.com/securego/gosec/v2/cmd/gosec@latest" >&2
    return 1
  fi
  cd "$REPO_ROOT"
  gosec \
    -fmt=json -out="$REPORTS_DIR/gosec.json" \
    -no-fail \
    ./cmd/... ./internal/... > /dev/null 2>&1 || true
  prettify "$REPORTS_DIR/gosec.json"
  gosec \
    -no-fail \
    ./cmd/... ./internal/... 2>&1 | sed -n '/Summary:/,$p'
}

run_checkov() {
  echo "==> checkov"
  # Сканим: Dockerfile (dockerfile-фреймворк) + .github/workflows/*.yml
  # (github_actions-фреймворк).
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/src" \
    -w /src \
    bridgecrew/checkov:latest \
    -d /src --framework dockerfile,github_actions \
    --quiet -o json --output-file-path /src/pipeline/_reports/ \
    > /dev/null 2>&1 || true
  if [ -f "$REPORTS_DIR/results_json.json" ]; then
    mv "$REPORTS_DIR/results_json.json" "$REPORTS_DIR/checkov.json"
    prettify "$REPORTS_DIR/checkov.json"
  fi
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$REPO_ROOT:/src" \
    -w /src \
    bridgecrew/checkov:latest \
    -d /src --framework dockerfile,github_actions \
    --quiet --compact 2>&1 | tail -40 || true
}

target="${1:-all}"
case "$target" in
  all)     run_semgrep; run_gosec; run_checkov ;;
  semgrep) run_semgrep ;;
  gosec)   run_gosec ;;
  checkov) run_checkov ;;
  *) echo "unknown target: $target (expected: all|semgrep|gosec|checkov)" >&2; exit 2 ;;
esac

echo
echo "Reports → $REPORTS_DIR"
ls -la "$REPORTS_DIR"

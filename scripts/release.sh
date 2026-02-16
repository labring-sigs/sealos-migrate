#!/usr/bin/env bash
# 用于根据 release.json 构建 Linux 双架构二进制并生成 md5 的发布脚本。
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG_PATH="${RELEASE_CONFIG:-${ROOT_DIR}/release.json}"
DIST_DIR="${DIST_DIR:-${ROOT_DIR}/dist}"
ARCHES=("amd64" "arm64")

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing required command: ${name}" >&2
    exit 1
  fi
}

write_md5() {
  local file="$1"
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$file" | awk '{print $1}' > "${file}.md5"
    return
  fi
  if command -v md5 >/dev/null 2>&1; then
    md5 -q "$file" > "${file}.md5"
    return
  fi
  echo "missing md5 tool (md5sum or md5)" >&2
  exit 1
}

run_optimize() {
  local file="$1"
  local optimize_cmd="$2"
  if [[ -z "$optimize_cmd" ]]; then
    return
  fi
  if [[ "$optimize_cmd" == *"{bin}"* ]]; then
    optimize_cmd="${optimize_cmd//\{bin\}/$file}"
  else
    optimize_cmd="${optimize_cmd} ${file}"
  fi
  echo "optimize: ${optimize_cmd}"
  eval "$optimize_cmd"
}

main() {
  require_cmd jq
  require_cmd go

  if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "release config not found: ${CONFIG_PATH}" >&2
    exit 1
  fi

  # optimize_cmd 为空时跳过优化，可使用 {bin} 占位符，例如:
  # optimize_cmd: "upx --best {bin}"
  local optimize_cmd
  optimize_cmd=$(jq -r '.optimize_cmd // empty' "$CONFIG_PATH")

  rm -rf "$DIST_DIR"
  mkdir -p "$DIST_DIR"

  if [[ $(jq '.targets | length' "$CONFIG_PATH") -lt 1 ]]; then
    echo "no targets defined in ${CONFIG_PATH}" >&2
    exit 1
  fi

  while IFS= read -r target; do
    local dir
    local bin
    dir=$(jq -r '.dir' <<< "$target")
    bin=$(jq -r '.binary' <<< "$target")
    if [[ -z "$dir" || -z "$bin" || "$dir" == "null" || "$bin" == "null" ]]; then
      echo "invalid target: ${target}" >&2
      exit 1
    fi

    for arch in "${ARCHES[@]}"; do
      local output
      output="${DIST_DIR}/${bin}-linux-${arch}"
      CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
        go -C "${ROOT_DIR}/${dir}" build -trimpath -ldflags "-s -w" -o "$output" .
      run_optimize "$output" "$optimize_cmd"
      write_md5 "$output"
    done
  done < <(jq -c '.targets[]' "$CONFIG_PATH")

  echo "artifacts available in ${DIST_DIR}"
}

main "$@"

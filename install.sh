#!/usr/bin/env bash

set -euo pipefail

APP_NAME="xiic-ssh-manager-desktop"
APPROVAL_APP_NAME="xiic-ssh-approval"
HELPER_NAME="xiic-ssh-mcp"
DEFAULT_INSTALL_ROOT="${HOME}/.local"
DEFAULT_GITHUB_REPOSITORY=""

usage() {
  cat <<'EOF'
Install Xiic SSH Manager from a local checkout or from GitHub Releases.

Usage:
  ./install.sh [--root <install-root>] [--debug]
  curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/install.sh | bash -s -- --repo <owner>/<repo>

Options:
  --root <install-root>  Install root. Binary will be copied to <root>/bin. Default: ~/.local
  --repo <owner/repo>    GitHub repository slug used for release downloads
  --version <tag>        Release tag to install. Default: latest
  --debug                Build the debug profile instead of release when installing from source
  -h, --help             Show this help message

The installed binaries will be:
  <install-root>/bin/xiic-ssh-manager-desktop
  <install-root>/bin/xiic-ssh-approval
  <install-root>/bin/xiic-ssh-mcp
EOF
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

log() {
  printf '==> %s\n' "$1"
}

INSTALL_ROOT="${DEFAULT_INSTALL_ROOT}"
BUILD_MODE="release"
GITHUB_REPOSITORY="${DEFAULT_GITHUB_REPOSITORY}"
VERSION="latest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || fail "--root requires a value"
      INSTALL_ROOT="$2"
      shift 2
      ;;
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires a value"
      GITHUB_REPOSITORY="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || fail "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --debug)
      BUILD_MODE="debug"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_CARGO_TOML="${SCRIPT_DIR}/Cargo.toml"
TAURI_CARGO_TOML="${SCRIPT_DIR}/src-tauri/Cargo.toml"

is_local_checkout() {
  [[ -f "${ROOT_CARGO_TOML}" ]] && [[ -f "${TAURI_CARGO_TOML}" ]]
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}" in
    Linux)
      case "${arch}" in
        x86_64) printf 'x86_64-unknown-linux-gnu\n' ;;
        aarch64|arm64) printf 'aarch64-unknown-linux-gnu\n' ;;
        *) fail "unsupported Linux architecture: ${arch}" ;;
      esac
      ;;
    Darwin)
      case "${arch}" in
        x86_64) printf 'x86_64-apple-darwin\n' ;;
        arm64) printf 'aarch64-apple-darwin\n' ;;
        *) fail "unsupported macOS architecture: ${arch}" ;;
      esac
      ;;
    *)
      fail "unsupported operating system: ${os}"
      ;;
  esac
}

ensure_path_hint() {
  case ":${PATH}:" in
    *":${INSTALL_ROOT}/bin:"*)
      ;;
    *)
      printf '\nAdd this directory to your PATH if needed:\n'
      printf '  export PATH="%s/bin:$PATH"\n' "${INSTALL_ROOT}"
      ;;
  esac
}

print_success() {
  local app_install_path="$1"
  local approval_install_path="$2"
  local helper_install_path="$3"

  log "Installed desktop binary: ${app_install_path}"
  log "Installed approval binary: ${approval_install_path}"
  log "Installed MCP helper: ${helper_install_path}"
  ensure_path_hint

  cat <<EOF

Launch the desktop app with:
  ${app_install_path}

After the app starts, copy the ready-to-paste STDIO MCP JSON from the UI.
EOF
}

install_from_source() {
  command -v npm >/dev/null 2>&1 || fail "npm is required but was not found in PATH"
  command -v cargo >/dev/null 2>&1 || fail "cargo is required but was not found in PATH"

  mkdir -p "${INSTALL_ROOT}/bin"

  if [[ ! -d "${SCRIPT_DIR}/node_modules" ]]; then
    log "Installing frontend dependencies"
    (cd "${SCRIPT_DIR}" && npm install)
  fi

  log "Building frontend"
  (cd "${SCRIPT_DIR}" && npm run build)

  log "Building STDIO MCP helper"
  if [[ "${BUILD_MODE}" == "release" ]]; then
    (cd "${SCRIPT_DIR}" && cargo build --release)
  else
    (cd "${SCRIPT_DIR}" && cargo build)
  fi

  log "Building Tauri desktop binary"
  if [[ "${BUILD_MODE}" == "release" ]]; then
    (cd "${SCRIPT_DIR}" && cargo build --manifest-path src-tauri/Cargo.toml --release)
    (cd "${SCRIPT_DIR}" && cargo build --manifest-path approval-tauri/Cargo.toml --release)
    cp "${SCRIPT_DIR}/src-tauri/target/release/${APP_NAME}" "${INSTALL_ROOT}/bin/${APP_NAME}"
    cp "${SCRIPT_DIR}/approval-tauri/target/release/${APPROVAL_APP_NAME}" "${INSTALL_ROOT}/bin/${APPROVAL_APP_NAME}"
    cp "${SCRIPT_DIR}/target/release/${HELPER_NAME}" "${INSTALL_ROOT}/bin/${HELPER_NAME}"
  else
    (cd "${SCRIPT_DIR}" && cargo build --manifest-path src-tauri/Cargo.toml)
    (cd "${SCRIPT_DIR}" && cargo build --manifest-path approval-tauri/Cargo.toml)
    cp "${SCRIPT_DIR}/src-tauri/target/debug/${APP_NAME}" "${INSTALL_ROOT}/bin/${APP_NAME}"
    cp "${SCRIPT_DIR}/approval-tauri/target/debug/${APPROVAL_APP_NAME}" "${INSTALL_ROOT}/bin/${APPROVAL_APP_NAME}"
    cp "${SCRIPT_DIR}/target/debug/${HELPER_NAME}" "${INSTALL_ROOT}/bin/${HELPER_NAME}"
  fi

  chmod 755 "${INSTALL_ROOT}/bin/${APP_NAME}"
  chmod 755 "${INSTALL_ROOT}/bin/${APPROVAL_APP_NAME}"
  chmod 755 "${INSTALL_ROOT}/bin/${HELPER_NAME}"
  print_success "${INSTALL_ROOT}/bin/${APP_NAME}" "${INSTALL_ROOT}/bin/${APPROVAL_APP_NAME}" "${INSTALL_ROOT}/bin/${HELPER_NAME}"
}

install_from_release() {
  command -v curl >/dev/null 2>&1 || fail "curl is required but was not found in PATH"
  command -v tar >/dev/null 2>&1 || fail "tar is required but was not found in PATH"
  command -v install >/dev/null 2>&1 || fail "install is required but was not found in PATH"

  [[ -n "${GITHUB_REPOSITORY}" ]] || fail "missing GitHub repository slug; pass --repo <owner/repo> or set DEFAULT_GITHUB_REPOSITORY in install.sh before publishing"

  local target asset_name release_url tmp_dir archive_path extracted_app extracted_approval extracted_helper app_install_path approval_install_path helper_install_path
  target="$(detect_target)"
  asset_name="${APP_NAME}-${target}.tar.gz"

  if [[ "${VERSION}" == "latest" ]]; then
    release_url="https://github.com/${GITHUB_REPOSITORY}/releases/latest/download/${asset_name}"
  else
    release_url="https://github.com/${GITHUB_REPOSITORY}/releases/download/${VERSION}/${asset_name}"
  fi

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "'"${tmp_dir}"'"' EXIT
  archive_path="${tmp_dir}/${asset_name}"

  log "Downloading ${asset_name} from ${release_url}"
  curl --fail --location --silent --show-error "${release_url}" --output "${archive_path}"

  log "Extracting ${asset_name}"
  tar -xzf "${archive_path}" -C "${tmp_dir}"
  extracted_app="$(find "${tmp_dir}" -type f -name "${APP_NAME}" | head -n 1)"
  extracted_approval="$(find "${tmp_dir}" -type f -name "${APPROVAL_APP_NAME}" | head -n 1)"
  extracted_helper="$(find "${tmp_dir}" -type f -name "${HELPER_NAME}" | head -n 1)"
  [[ -n "${extracted_app}" ]] || fail "downloaded archive did not contain ${APP_NAME}"
  [[ -n "${extracted_approval}" ]] || fail "downloaded archive did not contain ${APPROVAL_APP_NAME}"
  [[ -n "${extracted_helper}" ]] || fail "downloaded archive did not contain ${HELPER_NAME}"

  mkdir -p "${INSTALL_ROOT}/bin"
  app_install_path="${INSTALL_ROOT}/bin/${APP_NAME}"
  approval_install_path="${INSTALL_ROOT}/bin/${APPROVAL_APP_NAME}"
  helper_install_path="${INSTALL_ROOT}/bin/${HELPER_NAME}"
  install -m 755 "${extracted_app}" "${app_install_path}"
  install -m 755 "${extracted_approval}" "${approval_install_path}"
  install -m 755 "${extracted_helper}" "${helper_install_path}"
  print_success "${app_install_path}" "${approval_install_path}" "${helper_install_path}"
}

if [[ -z "${GITHUB_REPOSITORY}" ]] && is_local_checkout; then
  install_from_source
else
  install_from_release
fi

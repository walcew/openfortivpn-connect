#!/usr/bin/env bash
# Build openfortivpn with statically linked OpenSSL for bundling.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT}/src-tauri/binaries"
OUT_BIN="${OUT_DIR}/openfortivpn"
OUT_VERSION_FILE="${OUT_DIR}/openfortivpn.version"
# Use OPENFORTIVPN_VERSION=latest (default) to track the newest GitHub release tag,
# or pin e.g. OPENFORTIVPN_VERSION=v1.24.1 for reproducible builds.
VERSION_REQUEST="${OPENFORTIVPN_VERSION:-latest}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.3.2}"
DEPLOY_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
BUILD_ROOT="${OPENFORTIVPN_BUILD_DIR:-${TMPDIR:-/tmp}/openfortivpn-connect-build}"
SRC_DIR="${BUILD_ROOT}/openfortivpn"

HOST_ARCH="$(uname -m)"
ARCH="${HOST_ARCH}"
if [[ "${1:-}" == "x86_64" || "${1:-}" == "aarch64" || "${1:-}" == "arm64" ]]; then
  case "$1" in
    aarch64|arm64) ARCH="arm64" ;;
    x86_64) ARCH="x86_64" ;;
  esac
fi

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

resolve_openfortivpn_version() {
  local requested="$1"
  if [[ "${requested}" != "latest" ]]; then
    echo "${requested}"
    return
  fi
  local tag=""
  # Prefer GitHub Releases; many openfortivpn tags are published as releases.
  tag="$(curl -fsSL https://api.github.com/repos/adrienverge/openfortivpn/releases/latest 2>/dev/null \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -1 || true)"
  if [[ -z "${tag}" ]]; then
    # Fallback: newest version tag from the repo (works even without Releases API).
    tag="$(git ls-remote --tags --refs https://github.com/adrienverge/openfortivpn.git \
      | awk -F/ '{print $NF}' \
      | grep -E '^v?[0-9]+(\.[0-9]+)*$' \
      | sort -V \
      | tail -1 || true)"
  fi
  if [[ -z "${tag}" ]]; then
    echo "error: could not resolve latest openfortivpn release tag" >&2
    exit 1
  fi
  echo "${tag}"
}

VERSION="$(resolve_openfortivpn_version "${VERSION_REQUEST}")"
echo "openfortivpn version: ${VERSION} (requested: ${VERSION_REQUEST})"

if [[ -x "${OUT_BIN}" && "${FORCE_REBUILD:-}" != "1" ]]; then
  cached_version=""
  [[ -f "${OUT_VERSION_FILE}" ]] && cached_version="$(tr -d '[:space:]' < "${OUT_VERSION_FILE}")"
  if [[ "${cached_version}" == "${VERSION}" ]] && file "${OUT_BIN}" | grep -q "${ARCH}"; then
    echo "Using cached ${OUT_BIN} (${VERSION})"
    otool -L "${OUT_BIN}" || true
    exit 0
  fi
fi

# openfortivpn autogen needs autoconf + automake.
# Order: PATH → Homebrew (fast) → bootstrap from GNU sources with Xcode CLT (slow).
M4_VERSION="${M4_VERSION:-1.4.19}"
AUTOCONF_VERSION="${AUTOCONF_VERSION:-2.72}"
AUTOMAKE_VERSION="${AUTOMAKE_VERSION:-1.17}"

have_autotools() {
  command -v autoconf >/dev/null && command -v automake >/dev/null && command -v aclocal >/dev/null
}

have_compiler_toolchain() {
  command -v clang >/dev/null && command -v make >/dev/null && command -v perl >/dev/null
}

build_gnu_package() {
  local name="$1"
  local version="$2"
  local url="$3"
  local tools_prefix="$4"
  local tar_path="${BUILD_ROOT}/src/${name}-${version}.tar.gz"
  local src_dir="${BUILD_ROOT}/src/${name}-${version}"

  [[ -f "${tar_path}" ]] || curl -fsSL -o "${tar_path}" "${url}"
  rm -rf "${src_dir}"
  tar xzf "${tar_path}" -C "${BUILD_ROOT}/src"
  (
    cd "${src_dir}"
    ./configure --prefix="${tools_prefix}"
    make -j"$(sysctl -n hw.ncpu)"
    make install
  )
}

ensure_autotools() {
  if have_autotools; then
    echo "Using system autotools: $(autoconf --version | head -1), $(automake --version | head -1)"
    return
  fi

  local tools_prefix="${BUILD_ROOT}/host-tools"
  local tools_bin="${tools_prefix}/bin"
  if [[ -x "${tools_bin}/autoconf" && -x "${tools_bin}/automake" ]]; then
    export PATH="${tools_bin}:${PATH}"
    echo "Using cached autotools at ${tools_prefix}"
    return
  fi

  # Prefer Homebrew when available: much faster than bootstrapping GNU m4/autoconf.
  if command -v brew >/dev/null; then
    echo "Installing autoconf/automake via Homebrew..."
    brew list --formula autoconf &>/dev/null || brew install autoconf
    brew list --formula automake &>/dev/null || brew install automake
    # Ensure brew's bin is visible even in restricted PATH environments.
    local brew_prefix
    brew_prefix="$(brew --prefix)"
    export PATH="${brew_prefix}/bin:${PATH}"
    if have_autotools; then
      echo "Using Homebrew autotools: $(autoconf --version | head -1), $(automake --version | head -1)"
      return
    fi
  fi

  if ! have_compiler_toolchain; then
    cat >&2 <<'EOF'
error: cannot build bundled openfortivpn without a toolchain.

Need one of:
  - Homebrew (brew install autoconf automake), or
  - Xcode Command Line Tools (clang/make/perl) to bootstrap autotools

End users installing the DMG do not need either.
EOF
    exit 1
  fi

  echo "Bootstrapping m4/autoconf/automake with Xcode CLT (slow, first time only)..."
  mkdir -p "${BUILD_ROOT}/src" "${tools_prefix}"
  export PATH="${tools_bin}:${PATH}"

  if [[ ! -x "${tools_bin}/m4" ]]; then
    build_gnu_package m4 "${M4_VERSION}" \
      "https://ftp.gnu.org/gnu/m4/m4-${M4_VERSION}.tar.gz" \
      "${tools_prefix}"
  fi
  if [[ ! -x "${tools_bin}/autoconf" ]]; then
    build_gnu_package autoconf "${AUTOCONF_VERSION}" \
      "https://ftp.gnu.org/gnu/autoconf/autoconf-${AUTOCONF_VERSION}.tar.gz" \
      "${tools_prefix}"
  fi
  if [[ ! -x "${tools_bin}/automake" ]]; then
    build_gnu_package automake "${AUTOMAKE_VERSION}" \
      "https://ftp.gnu.org/gnu/automake/automake-${AUTOMAKE_VERSION}.tar.gz" \
      "${tools_prefix}"
  fi

  have_autotools || {
    echo "error: failed to bootstrap autotools" >&2
    exit 1
  }
}

resolve_openssl() {
  # Always build OpenSSL from source so the deployment target matches
  # (Homebrew bottles may require a newer macOS than we support).
  OPENSSL_PREFIX="${BUILD_ROOT}/openssl-${OPENSSL_VERSION}-${ARCH}-min${DEPLOY_TARGET}"
  if [[ -f "${OPENSSL_PREFIX}/lib/libssl.a" && -f "${OPENSSL_PREFIX}/lib/libcrypto.a" ]]; then
    echo "Using cached OpenSSL at ${OPENSSL_PREFIX}"
    return
  fi

  if ! have_compiler_toolchain; then
    echo "error: OpenSSL build needs clang, make, and perl (Xcode Command Line Tools)" >&2
    exit 1
  fi

  local openssl_src="${BUILD_ROOT}/openssl-${OPENSSL_VERSION}"
  local openssl_tarball="${BUILD_ROOT}/openssl-${OPENSSL_VERSION}.tar.gz"
  if [[ ! -f "${openssl_tarball}" ]]; then
    curl -fsSL -o "${openssl_tarball}" \
      "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
  fi

  local openssl_target
  case "${ARCH}" in
    arm64) openssl_target="darwin64-arm64-cc" ;;
    x86_64) openssl_target="darwin64-x86_64-cc" ;;
    *) echo "Unsupported arch: ${ARCH}" >&2; exit 1 ;;
  esac

  echo "Building OpenSSL ${OPENSSL_VERSION} (${openssl_target}, min ${DEPLOY_TARGET})..."
  # Fresh tree avoids stale Makefiles / accidental Homebrew link flags.
  rm -rf "${openssl_src}" "${OPENSSL_PREFIX}"
  tar xzf "${openssl_tarball}" -C "${BUILD_ROOT}"
  (
    cd "${openssl_src}"
    # Prevent Homebrew OpenSSL from leaking into this build via the ambient env.
    unset LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH \
      LDFLAGS CPPFLAGS CFLAGS PKG_CONFIG_PATH PKG_CONFIG_LIBDIR || true
    export CC="clang -arch ${ARCH}"
    ./Configure "${openssl_target}" no-shared no-module no-tests \
      --prefix="${OPENSSL_PREFIX}" \
      -mmacosx-version-min="${DEPLOY_TARGET}"
    make -j"$(sysctl -n hw.ncpu)"
    make install_sw
  )
}

mkdir -p "${BUILD_ROOT}" "${OUT_DIR}"
resolve_openssl
ensure_autotools

if [[ ! -d "${SRC_DIR}/.git" ]]; then
  rm -rf "${SRC_DIR}"
  git clone --depth 1 --branch "${VERSION}" https://github.com/adrienverge/openfortivpn.git "${SRC_DIR}"
else
  git -C "${SRC_DIR}" fetch --depth 1 origin "refs/tags/${VERSION}:refs/tags/${VERSION}" 2>/dev/null || true
  git -C "${SRC_DIR}" checkout -f "${VERSION}"
fi

cd "${SRC_DIR}"
if [[ ! -f configure ]]; then
  ./autogen.sh
fi

export MACOSX_DEPLOYMENT_TARGET="${DEPLOY_TARGET}"
export CC="clang -arch ${ARCH} -mmacosx-version-min=${DEPLOY_TARGET}"
# Stop pkg-config from injecting Homebrew OpenSSL beside our static libs.
export PKG_CONFIG_PATH=""
export PKG_CONFIG_LIBDIR="/nonexistent"
unset LIBRARY_PATH LDFLAGS CPPFLAGS CFLAGS || true

SSL_A="${OPENSSL_PREFIX}/lib/libssl.a"
CRYPTO_A="${OPENSSL_PREFIX}/lib/libcrypto.a"
[[ -f "${SSL_A}" && -f "${CRYPTO_A}" ]] || {
  echo "error: static OpenSSL libs missing under ${OPENSSL_PREFIX}" >&2
  exit 1
}

make distclean >/dev/null 2>&1 || true
./configure \
  --prefix="${BUILD_ROOT}/prefix" \
  OPENSSL_CFLAGS="-I${OPENSSL_PREFIX}/include" \
  OPENSSL_LIBS="${SSL_A} ${CRYPTO_A}"

if ! grep -q "${OPENSSL_PREFIX}/lib/libssl.a" Makefile; then
  echo "error: openfortivpn Makefile is not using bundled OpenSSL" >&2
  grep -n 'OPENSSL\|libssl\|libcrypto' Makefile | head -40 >&2 || true
  exit 1
fi
if grep -q '/opt/homebrew/.*/openssl' Makefile; then
  echo "error: openfortivpn Makefile still references Homebrew OpenSSL" >&2
  exit 1
fi

make -j"$(sysctl -n hw.ncpu)"
strip -x openfortivpn 2>/dev/null || strip openfortivpn

if otool -L openfortivpn | grep -qiE 'openssl|libssl|libcrypto'; then
  echo "error: openfortivpn still links OpenSSL dynamically" >&2
  otool -L openfortivpn >&2
  exit 1
fi

cp -f openfortivpn "${OUT_BIN}"
chmod 755 "${OUT_BIN}"
printf '%s\n' "${VERSION}" > "${OUT_VERSION_FILE}"
echo "Built ${OUT_BIN} ($(du -h "${OUT_BIN}" | awk '{print $1}')) [${VERSION}]"
file "${OUT_BIN}"
otool -L "${OUT_BIN}"
# Rosetta may be needed to execute a cross-built binary on Apple Silicon.
if file "${OUT_BIN}" | grep -q "$(uname -m)"; then
  "${OUT_BIN}" --version
fi

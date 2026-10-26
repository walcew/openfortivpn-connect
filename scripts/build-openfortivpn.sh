#!/usr/bin/env bash
# Compila o openfortivpn com OpenSSL estático para o bundle (ADR 0001).
# Uso: scripts/build-openfortivpn.sh [arm64|x86_64]
# Sem argumento, lê OPENFORTIVPN_ARCH e, por fim, a arquitetura do host.
set -euo pipefail

OPENFORTIVPN_VERSION=1.24.1
OPENSSL_VERSION=3.5.9
# Os overrides por env existem só para o teste de checksum do CI.
OPENFORTIVPN_SHA256="${OPENFORTIVPN_SHA256:-c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465}"
OPENSSL_SHA256="${OPENSSL_SHA256:-603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a}"
export MACOSX_DEPLOYMENT_TARGET=12.0

ARCH="${1:-${OPENFORTIVPN_ARCH:-$(uname -m)}}"
case "${ARCH}" in
  arm64|x86_64) ;;
  *) echo "usage: $0 [arm64|x86_64]" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT}/src-tauri/binaries"
OUT_BIN="${OUT_DIR}/openfortivpn"
STAMP_FILE="${OUT_DIR}/openfortivpn.version"
STAMP="openfortivpn-${OPENFORTIVPN_VERSION} openssl-${OPENSSL_VERSION} ${ARCH}"
BUILD_DIR="${ROOT}/.build-openfortivpn"

if [[ -x "${OUT_BIN}" && "$(cat "${STAMP_FILE}" 2>/dev/null)" == "${STAMP}" ]]; then
  echo "Up to date: ${OUT_BIN} (${STAMP})"
  exit 0
fi

# Baixa (se preciso) e confere o sha256; um tarball divergente é apagado para não ficar em cache.
fetch() {
  local url="$1" sha="$2" dest="$3" actual
  [[ -f "${dest}" ]] || curl -fsSL -o "${dest}" "${url}"
  actual="$(shasum -a 256 "${dest}" | awk '{print $1}')"
  if [[ "${actual}" != "${sha}" ]]; then
    echo "error: sha256 mismatch for $(basename "${dest}"): expected ${sha}, got ${actual}" >&2
    rm -f "${dest}"
    exit 1
  fi
}

mkdir -p "${BUILD_DIR}" "${OUT_DIR}"
OFV_TAR="${BUILD_DIR}/openfortivpn-${OPENFORTIVPN_VERSION}.tar.gz"
SSL_TAR="${BUILD_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
fetch "https://github.com/adrienverge/openfortivpn/archive/refs/tags/v${OPENFORTIVPN_VERSION}.tar.gz" \
  "${OPENFORTIVPN_SHA256}" "${OFV_TAR}"
fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
  "${OPENSSL_SHA256}" "${SSL_TAR}"

for tool in autoconf automake pkg-config make clang perl; do
  command -v "${tool}" >/dev/null || { echo "error: ${tool} is required" >&2; exit 1; }
done

WORK="${BUILD_DIR}/${ARCH}"
SSL_PREFIX="${WORK}/openssl"
rm -rf "${WORK}"
mkdir -p "${WORK}"
tar xzf "${OFV_TAR}" -C "${WORK}"
tar xzf "${SSL_TAR}" -C "${WORK}"

# Impede que flags do ambiente (ex.: Homebrew) puxem outro OpenSSL para o build.
unset LIBRARY_PATH CPATH C_INCLUDE_PATH LDFLAGS CPPFLAGS CFLAGS PKG_CONFIG_PATH
export PKG_CONFIG_LIBDIR=/nonexistent
export CC="clang -arch ${ARCH}"
JOBS="$(sysctl -n hw.ncpu)"

(
  cd "${WORK}/openssl-${OPENSSL_VERSION}"
  # --openssldir: o openssl.cnf e as CAs lidos como root vêm do diretório do sistema, de root,
  # e não do diretório de build gravável pelo usuário.
  ./Configure "darwin64-${ARCH}-cc" no-shared no-module no-tests no-docs \
    --prefix="${SSL_PREFIX}" --openssldir=/private/etc/ssl
  make -j"${JOBS}"
  make install_sw
)

(
  cd "${WORK}/openfortivpn-${OPENFORTIVPN_VERSION}"
  ./autogen.sh
  # --sysconfdir=/etc: o config padrão lido como root precisa estar num diretório de root.
  # --enable-legacy-pppd: o pppd do macOS é < 2.5.0.
  ./configure --sysconfdir=/etc --enable-legacy-pppd \
    OPENSSL_CFLAGS="-I${SSL_PREFIX}/include" \
    OPENSSL_LIBS="${SSL_PREFIX}/lib/libssl.a ${SSL_PREFIX}/lib/libcrypto.a"
  make -j"${JOBS}"
)

BIN="${WORK}/openfortivpn-${OPENFORTIVPN_VERSION}/openfortivpn"
otool -L "${BIN}"
# Só bibliotecas do sistema: nada de OpenSSL dinâmico nem caminhos graváveis pelo usuário.
if otool -L "${BIN}" | tail -n +2 | grep -vE '^[[:space:]]+(/usr/lib/|/System/Library/)'; then
  echo "error: openfortivpn links non-system libraries (listed above)" >&2
  exit 1
fi

install -m 755 "${BIN}" "${OUT_BIN}"
printf '%s\n' "${STAMP}" > "${STAMP_FILE}"
echo "Built ${OUT_BIN} (${STAMP})"

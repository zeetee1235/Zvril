#!/bin/sh
# Install the build and test dependencies for Zvril on Ubuntu.
# Usage: sudo ./scripts/install-deps-ubuntu.sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
  SUDO=
else
  SUDO=sudo
fi

. /etc/os-release
if [ "${ID:-}" != "ubuntu" ]; then
  echo "This script is for Ubuntu; detected ${ID:-unknown}" >&2
  exit 1
fi
case "${VERSION_CODENAME:-}" in
  noble|jammy) ;;
  *)
    echo "Ubuntu ${VERSION_CODENAME:-unknown} is not tested; use noble or jammy" >&2
    exit 1
    ;;
esac

$SUDO apt-get update
$SUDO apt-get install -y \
  wget ca-certificates gnupg lsb-release build-essential cmake ninja-build \
  python3 libzstd-dev zlib1g-dev binutils git

wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key |
  $SUDO tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc >/dev/null
echo "deb http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-22 main" |
  $SUDO tee /etc/apt/sources.list.d/llvm-22.list >/dev/null
$SUDO apt-get update
$SUDO apt-get install -y clang-22 llvm-22-dev llvm-22

gcc_major="$(gcc -dumpversion | cut -d. -f1)"
$SUDO apt-get install -y "libstdc++-${gcc_major}-dev"

echo "Installed LLVM 22 and static libstdc++ (GCC ${gcc_major})."

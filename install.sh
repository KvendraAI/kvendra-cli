#!/bin/sh
# Install the Kvendra CLI from the GitHub Release binaries (ISSUE-KVD-CLI-97093A).
#
#   curl -fsSL https://raw.githubusercontent.com/KvendraAI/kvendra-cli/main/install.sh | sh
#
# Options (environment):
#   KVENDRA_VERSION      a tag such as v0.9.1 (default: the latest release)
#   KVENDRA_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
#
# The archive's sha256 is checked against the release before anything is installed.
# Windows: download the .zip from the release page instead.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

repo="KvendraAI/kvendra-cli"
install_dir="${KVENDRA_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'kvendra install: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" > /dev/null 2>&1 || fail "missing required command: $1"; }
need curl
need tar
need uname

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin) os_part="apple-darwin" ;;
  Linux) os_part="unknown-linux-gnu" ;;
  *) fail "unsupported OS: $os (on Windows, use the .zip from https://github.com/$repo/releases)" ;;
esac
case "$arch" in
  arm64 | aarch64) arch_part="aarch64" ;;
  x86_64 | amd64) arch_part="x86_64" ;;
  *) fail "unsupported CPU: $arch" ;;
esac
target="${arch_part}-${os_part}"

version="${KVENDRA_VERSION:-}"
if [ -z "$version" ]; then
  version="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$version" ] || fail "could not find the latest release"
fi

name="kvendra-${version}-${target}"
base="https://github.com/$repo/releases/download/${version}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading kvendra ${version} for ${target}..."
curl -fsSL -o "$tmp/${name}.tar.gz" "${base}/${name}.tar.gz" \
  || fail "no binary for ${target} in ${version}"
curl -fsSL -o "$tmp/${name}.tar.gz.sha256" "${base}/${name}.tar.gz.sha256" \
  || fail "no checksum for ${name}.tar.gz"

expected="$(cut -d' ' -f1 < "$tmp/${name}.tar.gz.sha256")"
if command -v sha256sum > /dev/null 2>&1; then
  actual="$(sha256sum "$tmp/${name}.tar.gz" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/${name}.tar.gz" | cut -d' ' -f1)"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${name}.tar.gz"

tar -xzf "$tmp/${name}.tar.gz" -C "$tmp"
mkdir -p "$install_dir"
mv "$tmp/${name}/kvendra" "$install_dir/kvendra"
chmod +x "$install_dir/kvendra"

say "Installed: $install_dir/kvendra"
"$install_dir/kvendra" --version || true
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) say "Add $install_dir to your PATH, e.g.: export PATH=\"$install_dir:\$PATH\"" ;;
esac

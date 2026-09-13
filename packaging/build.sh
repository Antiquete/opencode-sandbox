#!/usr/bin/env bash
set -euo pipefail

VER="${VER:?set VER, e.g. VER=1.0.0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REPO_URL="${REPO_URL:-$(git -C "$ROOT" remote get-url origin 2>/dev/null || true)}"
if [ -z "$REPO_URL" ]; then
    echo "Error: no git remote 'origin' (set REPO_URL to override)." >&2
    exit 1
fi
HOMEPAGE="${REPO_URL%.git}"
case "$HOMEPAGE" in
    git@*)
        HOMEPAGE="${HOMEPAGE#git@}"
        HOMEPAGE="https://${HOMEPAGE/:/\//}"
        ;;
esac
GIT_NAME="$(git -C "$ROOT" config user.name 2>/dev/null || true)"
GIT_EMAIL="$(git -C "$ROOT" config user.email 2>/dev/null || true)"
MAINTAINER="${MAINTAINER:-$GIT_NAME ${MAINTAINER_EMAIL:-$GIT_EMAIL}}"
[ -n "$(printf '%s' "$MAINTAINER" | tr -d '[:space:]')" ] || MAINTAINER="OpenCode Sandbox Maintainers"

DIST="$ROOT/dist"
PKG=/tmp/opencode-sandbox
rm -rf "$DIST" "$PKG"
mkdir -p "$DIST" "$PKG/usr/bin"

install -m 0755 opencode-sandbox "$PKG/usr/bin/"
install -m 0755 opencode-project-init "$PKG/usr/bin/"

echo "== source tarball =="
mkdir -p "$PKG/opencode-sandbox-$VER"
cp opencode-sandbox opencode-project-init README.md LICENSE "$PKG/opencode-sandbox-$VER/"
tar -czf "$DIST/opencode-sandbox-$VER.tar.gz" -C "$PKG" opencode-sandbox-$VER

echo "== .deb =="
DEB=/tmp/deb
mkdir -p "$DEB/DEBIAN" "$DEB/usr/bin"
cp "$PKG/usr/bin"/* "$DEB/usr/bin/"
cat > "$DEB/DEBIAN/control" <<EOF
Package: opencode-sandbox
Version: $VER
Section: utils
Priority: optional
Architecture: all
Depends: bash, docker-ce
Maintainer: $MAINTAINER
Description: Run OpenCode inside an isolated Docker sandbox
 Runs opencode.ai in a locked-down Docker container with access
 limited to the current project.
EOF
dpkg-deb -b --root-owner-group "$DEB" "$DIST/opencode-sandbox_${VER}_all.deb"

echo "== .rpm =="
RPM=/tmp/rpmbuild
mkdir -p "$RPM/SPECS" "$RPM/SOURCES"
cp opencode-sandbox opencode-project-init "$RPM/SOURCES/"
cat > "$RPM/SPECS/opencode-sandbox.spec" <<EOF
Name: opencode-sandbox
Version: $VER
Release: 1
Summary: Run OpenCode inside an isolated Docker sandbox
License: GPL-3.0-or-later
URL: $HOMEPAGE
BuildArch: noarch
Requires: bash, docker-ce

%define __os_install_post %{nil}

%description
Run opencode.ai inside a locked-down Docker container with access
limited to the current project.

%install
install -d %{buildroot}/usr/bin
install -m 0755 %{_sourcedir}/opencode-sandbox %{buildroot}/usr/bin/
install -m 0755 %{_sourcedir}/opencode-project-init %{buildroot}/usr/bin/

%files
/usr/bin/opencode-sandbox
/usr/bin/opencode-project-init
EOF
rpmbuild -bb --define "_topdir $RPM" "$RPM/SPECS/opencode-sandbox.spec" >/dev/null
cp "$RPM"/RPMS/noarch/*.rpm "$DIST/"

echo "== .pkg.tar.zst (Arch) =="
ARC=/tmp/arch
mkdir -p "$ARC/usr/bin"
cp "$PKG/usr/bin"/* "$ARC/usr/bin/"
cat > "$ARC/.PKGINFO" <<EOF
pkgname = opencode-sandbox
pkgver = $VER
pkgdesc = Run OpenCode inside an isolated Docker sandbox
url = $HOMEPAGE
builddate = $(date -u +%s)
packager = $MAINTAINER
size = $(du -sb "$ARC" | cut -f1)
arch = any
license = GPL-3.0-or-later
depend = bash
depend = docker
EOF
(
    cd "$ARC"
    bsdtar -cf .MTREE --format=mtree --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256' .PKGINFO usr
    tar --zstd -cf "$DIST/opencode-sandbox-${VER}-1-any.pkg.tar.zst" .PKGINFO .MTREE usr
)

echo "== ebuild (Gentoo) =="
cat > "$DIST/opencode-sandbox-${VER}.ebuild" <<EOF
EAPI=8

DESCRIPTION="Run OpenCode inside an isolated Docker sandbox"
HOMEPAGE="$HOMEPAGE"
SRC_URI="$HOMEPAGE/releases/download/v${VER}/opencode-sandbox-${VER}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~arm64"
RESTRICT="network-sandbox"

RDEPEND="app-shells/bash virtual/docker"

src_install() {
    dobin opencode-sandbox opencode-project-init
}
EOF

echo
ls -la "$DIST"
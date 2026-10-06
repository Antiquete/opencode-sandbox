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
	HOMEPAGE="https://${HOMEPAGE/:/\/}"
	;;
esac
GIT_NAME="$(git -C "$ROOT" config user.name 2>/dev/null || true)"
GIT_EMAIL="$(git -C "$ROOT" config user.email 2>/dev/null || true)"
MAINTAINER="${MAINTAINER:-$GIT_NAME ${MAINTAINER_EMAIL:-$GIT_EMAIL}}"
[ -n "$(printf '%s' "$MAINTAINER" | tr -d '[:space:]')" ] || MAINTAINER="OpenCode Sandbox Maintainers"

DIST="$ROOT/dist"
PKG="$(mktemp -d "${TMPDIR:-/tmp}/opencode-package.XXXXXXXX")"
trap 'rm -rf -- "$PKG"' EXIT
# The guard binary is arch-specific, so the packages are too.
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
x86_64) DEB_ARCH=amd64 ;;
aarch64) DEB_ARCH=arm64 ;;
*) DEB_ARCH="$HOST_ARCH" ;;
esac

# Stage the launcher and init scripts for the binary packages.
stage_binaries() {
	mkdir -p "$PKG/usr/bin"
	install -m 0755 opencode-sandbox "$PKG/usr/bin/"
	install -m 0755 opencode-project-init "$PKG/usr/bin/"
}

# Build the static seccomp guard and stage it for the binary packages.
build_guard() {
	echo "== guard binary =="
	make
	install -D -m 0755 build/opencode-guard "$PKG/usr/lib/opencode-sandbox/guard"
}

build_tarball() {
	echo "== source tarball =="
	mkdir -p "$PKG/opencode-sandbox-$VER/build" "$PKG/opencode-sandbox-$VER/sandbox"
	cp opencode-sandbox opencode-project-init README.md LICENSE Makefile "$PKG/opencode-sandbox-$VER/"
	cp build/opencode-guard "$PKG/opencode-sandbox-$VER/build/"
	cp sandbox/guard.c "$PKG/opencode-sandbox-$VER/sandbox/"
	tar -czf "$DIST/opencode-sandbox-$VER.tar.gz" -C "$PKG" opencode-sandbox-$VER
}

build_deb() {
	echo "== .deb =="
	DEB="$PKG/deb"
	mkdir -p "$DEB/DEBIAN" "$DEB/usr/bin" "$DEB/usr/lib/opencode-sandbox"
	cp "$PKG/usr/bin"/* "$DEB/usr/bin/"
	cp "$PKG/usr/lib/opencode-sandbox/guard" "$DEB/usr/lib/opencode-sandbox/guard"
	cat >"$DEB/DEBIAN/control" <<EOF
Package: opencode-sandbox
Version: $VER
Section: utils
Priority: optional
Architecture: $DEB_ARCH
Depends: bash, docker-ce
Maintainer: $MAINTAINER
Description: Run OpenCode inside an isolated Docker sandbox
 Runs opencode.ai in a locked-down Docker container with access
 limited to the current project.
EOF
	dpkg-deb -b --root-owner-group "$DEB" "$DIST/opencode-sandbox_${VER}_$DEB_ARCH.deb"
}

build_rpm() {
	echo "== .rpm =="
	RPM="$PKG/rpmbuild"
	mkdir -p "$RPM/SPECS" "$RPM/SOURCES"
	cp opencode-sandbox opencode-project-init build/opencode-guard "$RPM/SOURCES/"
	cat >"$RPM/SPECS/opencode-sandbox.spec" <<EOF
Name: opencode-sandbox
Version: $VER
Release: 1
Summary: Run OpenCode inside an isolated Docker sandbox
License: GPL-3.0-or-later
URL: $HOMEPAGE
Requires: bash, docker-ce

%define __os_install_post %{nil}

%description
Run opencode.ai inside a locked-down Docker container with access
limited to the current project.

%install
install -d %{buildroot}/usr/bin
install -d %{buildroot}/usr/lib/opencode-sandbox
install -m 0755 %{_sourcedir}/opencode-sandbox %{buildroot}/usr/bin/
install -m 0755 %{_sourcedir}/opencode-project-init %{buildroot}/usr/bin/
install -m 0755 %{_sourcedir}/opencode-guard %{buildroot}/usr/lib/opencode-sandbox/guard

%files
/usr/bin/opencode-sandbox
/usr/bin/opencode-project-init
/usr/lib/opencode-sandbox/guard
EOF
	rpmbuild -bb --define "_topdir $RPM" "$RPM/SPECS/opencode-sandbox.spec" >/dev/null
	cp "$RPM"/RPMS/*/*.rpm "$DIST/"
}

build_arch() {
	echo "== .pkg.tar.zst (Arch) =="
	ARC="$PKG/arch"
	mkdir -p "$ARC/usr/bin" "$ARC/usr/lib/opencode-sandbox"
	cp "$PKG/usr/bin"/* "$ARC/usr/bin/"
	cp "$PKG/usr/lib/opencode-sandbox/guard" "$ARC/usr/lib/opencode-sandbox/guard"
	cat >"$ARC/.PKGINFO" <<EOF
pkgname = opencode-sandbox
pkgver = $VER
pkgdesc = Run OpenCode inside an isolated Docker sandbox
url = $HOMEPAGE
builddate = $(date -u +%s)
packager = $MAINTAINER
size = $(du -sb "$ARC" | cut -f1)
arch = $HOST_ARCH
license = GPL-3.0-or-later
depend = bash
depend = docker
EOF
	(
		cd "$ARC"
		bsdtar -cf .MTREE --format=mtree --options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256' .PKGINFO usr
		tar --zstd -cf "$DIST/opencode-sandbox-${VER}-1-${HOST_ARCH}.pkg.tar.zst" .PKGINFO .MTREE usr
	)
}

build_gentoo() {
	echo "== ebuild (Gentoo) =="
	cat >"$DIST/opencode-sandbox-${VER}.ebuild" <<EOF
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
    exeinto /usr/lib/opencode-sandbox
    newexe build/opencode-guard guard
}
EOF
}

mkdir -p "$DIST"
stage_binaries
build_guard
build_tarball
build_deb
build_rpm
build_arch
build_gentoo

echo
ls -la "$DIST"

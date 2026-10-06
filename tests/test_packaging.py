"""Build real package artifacts in isolated directories and inspect their layouts."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "packaging/build.sh").read_text()
FUNCTIONS = SOURCE[SOURCE.index("stage_binaries() {"):SOURCE.index('\nmkdir -p "$DIST"')]
ARCH = platform.machine()


class PackagingTests(unittest.TestCase):
    def build(self, function, tools=()):
        for tool in tools:
            if not shutil.which(tool):
                if os.environ.get("REQUIRE_PACKAGE_TOOLS") == "1":
                    self.fail(f"required package tool unavailable: {tool}")
                self.skipTest(f"required package tool unavailable: {tool}")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        dist = base / "dist"
        dist.mkdir()
        env = {**os.environ, "PKG": str(base / "stage"),
               "DIST": str(dist), "VER": "0.0.0", "HOST_ARCH": ARCH,
               "DEB_ARCH": {"x86_64": "amd64", "aarch64": "arm64"}.get(ARCH, ARCH),
               "HOMEPAGE": "https://example.com", "MAINTAINER": "Package Test"}
        setup = '\nstage_binaries\ninstall -Dm755 build/opencode-guard "$PKG/usr/lib/opencode-sandbox/guard"\n'
        result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + FUNCTIONS + setup + function],
                                cwd=ROOT, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return dist

    def test_tarball(self):
        dist = self.build("build_tarball")
        import tarfile
        with tarfile.open(dist / "opencode-sandbox-0.0.0.tar.gz") as archive:
            for name in ("opencode-sandbox", "opencode-project-init", "build/opencode-guard", "sandbox/guard.c", "Makefile"):
                member = archive.getmember("opencode-sandbox-0.0.0/" + name)
                self.assertTrue(member.isfile())
                self.assertEqual(archive.extractfile(member).read(), (ROOT / name).read_bytes())

    def test_deb(self):
        dist = self.build("build_deb", ("dpkg-deb",))
        package = next(dist.glob("*.deb"))
        listing = subprocess.check_output(["dpkg-deb", "-c", str(package)], text=True)
        self.assertIn("./usr/lib/opencode-sandbox/guard", listing)
        self.assertIn("./usr/bin/opencode-sandbox", listing)

    def test_rpm(self):
        dist = self.build("build_rpm", ("rpmbuild", "rpm"))
        listing = subprocess.check_output(["rpm", "-qlp", str(next(dist.glob("*.rpm")))], text=True)
        self.assertIn("/usr/lib/opencode-sandbox/guard", listing)
        self.assertIn("/usr/bin/opencode-sandbox", listing)

    def test_arch(self):
        dist = self.build("build_arch", ("bsdtar", "zstd"))
        package = dist / f"opencode-sandbox-0.0.0-1-{ARCH}.pkg.tar.zst"
        listing = subprocess.check_output(["bsdtar", "-tf", str(package)], text=True)
        self.assertIn("usr/lib/opencode-sandbox/guard", listing)
        metadata = subprocess.check_output(["bsdtar", "-xOf", str(package), ".PKGINFO"], text=True)
        self.assertIn(f"arch = {ARCH}\n", metadata)

    def test_gentoo(self):
        dist = self.build("build_gentoo")
        ebuild = dist / "opencode-sandbox-0.0.0.ebuild"
        subprocess.run(["bash", "-n", str(ebuild)], check=True)
        self.assertIn("newexe build/opencode-guard guard", ebuild.read_text())

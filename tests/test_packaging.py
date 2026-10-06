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
                                cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return dist

    def test_binary_guard_is_rebuilt_before_staging(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name)
        (source / "sandbox").mkdir()
        (source / "build").mkdir()
        shutil.copy2(ROOT / "Makefile", source / "Makefile")
        shutil.copy2(ROOT / "sandbox/guard.c", source / "sandbox/guard.c")
        guard = source / "build/opencode-guard"
        guard.write_bytes(b"incompatible prebuilt guard")
        os.utime(guard, (2000000000, 2000000000))
        result = subprocess.run(
            ["bash", "-ec", FUNCTIONS + "\nbuild_guard"], cwd=source,
            env={**os.environ, "PKG": str(source / "stage")},
            text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        staged = source / "stage/usr/lib/opencode-sandbox/guard"
        self.assertTrue(staged.read_bytes().startswith(b"\x7fELF"))
        self.assertEqual(staged.read_bytes(), guard.read_bytes())

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
        self.assertIn("./usr/share/doc/opencode-sandbox/copyright", listing)
        dependencies = subprocess.check_output(["dpkg-deb", "-f", str(package), "Depends"], text=True)
        self.assertEqual(dependencies.strip(), "bash, docker.io | docker-ce | podman")

    def test_rpm(self):
        dist = self.build("build_rpm", ("rpmbuild", "rpm"))
        package = next(dist.glob("*.rpm"))
        listing = subprocess.check_output(["rpm", "-qlp", str(package)], text=True)
        self.assertIn("/usr/lib/opencode-sandbox/guard", listing)
        self.assertIn("/usr/bin/opencode-sandbox", listing)
        self.assertIn("/usr/share/licenses/opencode-sandbox/LICENSE", listing)
        dependencies = subprocess.check_output(["rpm", "-qp", "--requires", str(package)], text=True)
        self.assertIn("(docker or docker-ce or podman)", dependencies)

    def test_arch(self):
        dist = self.build("build_arch", ("bsdtar", "zstd"))
        package = dist / f"opencode-sandbox-0.0.0-1-{ARCH}.pkg.tar.zst"
        listing = subprocess.check_output(["bsdtar", "-tf", str(package)], text=True)
        self.assertIn("usr/lib/opencode-sandbox/guard", listing)
        self.assertEqual(subprocess.check_output([
            "bsdtar", "-xOf", str(package), "usr/share/licenses/opencode-sandbox/LICENSE"
        ]), (ROOT / "LICENSE").read_bytes())
        metadata = subprocess.check_output(["bsdtar", "-xOf", str(package), ".PKGINFO"], text=True)
        self.assertIn(f"arch = {ARCH}\n", metadata)
        self.assertIn("pkgver = 0.0.0-1\n", metadata)
        self.assertIn("optdepend = docker: Docker runtime\n", metadata)
        self.assertIn("optdepend = podman: Podman runtime\n", metadata)
        self.assertNotIn("depend = docker\n", metadata)
        import tarfile
        archive = subprocess.check_output(["zstd", "-dc", str(package)])
        import io
        with tarfile.open(fileobj=io.BytesIO(archive)) as contents:
            for member in contents.getmembers():
                self.assertEqual((member.uid, member.gid), (0, 0), member.name)
        mtree = subprocess.check_output(["bsdtar", "-xOf", str(package), ".MTREE"], text=True)
        self.assertEqual({field for field in mtree.split()
                          if field.startswith(("uid=", "gid="))}, {"uid=0", "gid=0"})

    def test_gentoo(self):
        dist = self.build("build_tarball\nbuild_gentoo")
        ebuild = dist / "opencode-sandbox-0.0.0.ebuild"
        subprocess.run(["bash", "-n", str(ebuild)], check=True)
        self.assertIn("newexe build/opencode-guard guard", ebuild.read_text())
        self.assertIn("dodoc LICENSE", ebuild.read_text())
        self.assertIn("|| ( virtual/docker app-containers/podman )", ebuild.read_text())
        import tarfile
        with tarfile.open(dist / "opencode-sandbox-0.0.0.tar.gz") as archive:
            archive.extractall(dist, filter="data")
        source = dist / "opencode-sandbox-0.0.0"
        guard = source / "build/opencode-guard"
        guard.write_bytes(b"incompatible prebuilt guard")
        os.utime(guard, (2000000000, 2000000000))
        result = subprocess.run(
            ["bash", "-ec", 'source "$1"; emake() { make "$@"; }; src_compile',
             "bash", str(ebuild)], cwd=source, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(guard.read_bytes().startswith(b"\x7fELF"))

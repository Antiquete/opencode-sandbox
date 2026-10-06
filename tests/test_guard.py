"""Native-kernel guard regression tests (no container runtime needed).

Each test runs a snippet under build/opencode-guard on this host's kernel
using synthetic temporary files only — never host secrets. Docker-based
integration is a separate concern; these pin the supervisor's mechanism:
deny system-file content (including alias bypasses), keep normal I/O working,
and spoof uname/sysinfo.
"""
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "build/opencode-guard"


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="opencode-guard-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def guarded(self, code, *args, timeout=30, env_extra=None, placeholder=True):
        binary_dir = self.base / "bin"
        binary_dir.mkdir(exist_ok=True)
        opencode = binary_dir / "opencode"
        opencode.write_text(
            f"#!{sys.executable}\n"
            + code
        )
        opencode.chmod(0o755)
        env = os.environ.copy()
        env.pop("OPENCODE_GUARD_MEMORY", None)
        env["OPENCODE_SANDBOX"] = "1"
        if env_extra:
            env.update(env_extra)
        env["PATH"] = f"{binary_dir}:{env['PATH']}"
        return subprocess.run(["/opt/opencode-sandbox/guard", *(["opencode"] if placeholder else []), *map(str, args)],
                              executable=str(GUARD), cwd=self.base, env=env,
                              text=True, capture_output=True, timeout=timeout)

    def test_arguments_preserve_boundaries(self):
        result = self.guarded("import sys\nassert sys.argv[1:] == ['space value', '', 'a=b', '--flag']\n",
                              "space value", "", "a=b", "--flag")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_placeholder_is_rejected(self):
        result = self.guarded("raise AssertionError('workload started')", placeholder=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing command placeholder", result.stderr)

    def test_signals_are_forwarded(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGWINCH):
            with self.subTest(signal=sig):
                result = self.guarded(f"""
import os, signal, time
def received(sig, frame):
    print(sig, flush=True)
    raise SystemExit(23)
signal.signal({int(sig)}, received)
os.kill(os.getppid(), {int(sig)})
while True:
    time.sleep(1)
""", timeout=5)
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(result.stdout.strip(), str(int(sig)))

    def test_direct_invocation_is_rejected(self):
        env = os.environ.copy()
        env.pop("OPENCODE_SANDBOX", None)
        for marker in (None, "1"):
            with self.subTest(marker=marker):
                if marker:
                    env["OPENCODE_SANDBOX"] = marker
                result = subprocess.run(
                    [str(GUARD), "opencode"], env=env,
                    text=True, capture_output=True, timeout=5,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("run through opencode-sandbox", result.stderr)

    def test_entrypoint_without_marker_is_rejected(self):
        for marker in ("", "0"):
            with self.subTest(marker=marker):
                result = self.guarded("raise AssertionError('workload started')",
                                      env_extra={"OPENCODE_SANDBOX": marker})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("run through opencode-sandbox", result.stderr)

    def test_host_metadata_and_aliases_denied(self):
        (self.base / "alias").symlink_to("/proc/cmdline")
        (self.base / "stat-alias").symlink_to("/proc/self/stat")
        (self.base / "exe-alias").symlink_to("/proc/self/exe")
        (self.base / "net-alias").symlink_to("/sys/class/net")
        paths = ["/proc/cmdline", "/proc//cmdline", "/proc/./cmdline",
                 "/proc/cpuinfo", "/proc/meminfo", "/proc/partitions",
                 "/proc/diskstats", "/proc/modules", "/proc/version",
                 "/proc/uptime", "/proc/stat", "/proc/loadavg",
                 "/proc/sys/kernel/random/boot_id", "/proc/self/mountinfo",
                 "/proc/self/mounts", "/proc/1/mountinfo",
                 "/proc/1/status", "/proc/1/maps", "/proc/1/environ",
                 "/proc/self/stat", "/proc/self/auxv", "/proc/self/wchan",
                 "/proc/thread-self/mountinfo", "/proc/mounts",
                 "/proc/self/root/proc/cmdline", str(self.base / "alias"),
                 str(self.base / "stat-alias"), str(self.base / "exe-alias"),
                 "/sys/class/net", "/sys/fs/cgroup",
                 "/sys/devices/virtual/net", str(self.base / "net-alias"),
                 "/sys/kernel/kexec_loaded", "/sys/power/state"]
        result = self.guarded('''import os, sys
for path in sys.argv[1:]:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        assert e.errno in (13, 1, 2, 40), (path, e)
    else:
        os.close(fd)
        raise AssertionError("metadata opened: " + path)
''', *paths)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_metadata_only_path_syscalls_remain_unfiltered(self):
        result = self.guarded('''import os
assert os.stat('/proc/self/status')
assert os.access('/proc/self/status', os.R_OK)
assert os.stat('/sys')
assert os.access('/sys', os.R_OK)
assert os.path.isabs(os.readlink('/proc/self/exe'))
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_relative_opens_denied(self):
        result = self.guarded('''import os
try:
    os.open('/proc', os.O_RDONLY | os.O_DIRECTORY)
except PermissionError:
    pass
else:
    raise AssertionError('/proc directory opened')
os.chdir('/proc')
try:
    open('cmdline')
except PermissionError:
    pass
else:
    raise AssertionError('relative bypass')
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_normal_io_and_children_work_with_proc_sys_blocked(self):
        result = self.guarded('''import errno, os, subprocess, sys
with open('state', 'w') as f: f.write('persistent')
assert open('state').read() == 'persistent'
for path in ('/proc', '/proc/self/status', '/proc/self/stat', '/proc/self/exe',
             '/proc/net/tcp', '/sys', '/sys/class/net', '/sys/fs/cgroup'):
    try:
        open(path)
    except OSError as e:
        assert e.errno in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.ELOOP), (path, e)
    else:
        raise AssertionError('proc/sys path opened: ' + path)
child_code = "import os\\nwith open('child-state', 'w') as f: f.write('child ok')\\n"
open('child.py', 'w').write(child_code)
subprocess.run([sys.executable, '-B', 'child.py'], check=True)
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.base / "state").read_text(), "persistent")
        self.assertEqual((self.base / "child-state").read_text(), "child ok")

    def test_uname_and_sysinfo_are_synthetic(self):
        result = self.guarded('''import ctypes, os
u = os.uname()
assert u.nodename == 'opencode', u
assert u.release == '6.1.0-sandbox', u
class Info(ctypes.Structure):
    _fields_ = [('uptime', ctypes.c_long), ('loads', ctypes.c_ulong * 3),
                ('totalram', ctypes.c_ulong), ('freeram', ctypes.c_ulong),
                ('sharedram', ctypes.c_ulong), ('bufferram', ctypes.c_ulong),
                ('totalswap', ctypes.c_ulong), ('freeswap', ctypes.c_ulong),
                ('procs', ctypes.c_ushort), ('pad', ctypes.c_ushort),
                ('totalhigh', ctypes.c_ulong), ('freehigh', ctypes.c_ulong),
                ('mem_unit', ctypes.c_uint)]
info = Info()
assert ctypes.CDLL(None).sysinfo(ctypes.byref(info)) == 0
assert info.totalram * info.mem_unit == 4 * 1024**3
assert info.uptime < 120
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sysinfo_uses_configured_guard_memory(self):
        code = '''import ctypes, sys
class Info(ctypes.Structure):
    _fields_ = [('uptime', ctypes.c_long), ('loads', ctypes.c_ulong * 3),
                ('totalram', ctypes.c_ulong), ('freeram', ctypes.c_ulong),
                ('sharedram', ctypes.c_ulong), ('bufferram', ctypes.c_ulong),
                ('totalswap', ctypes.c_ulong), ('freeswap', ctypes.c_ulong),
                ('procs', ctypes.c_ushort), ('pad', ctypes.c_ushort),
                ('totalhigh', ctypes.c_ulong), ('freehigh', ctypes.c_ulong),
                ('mem_unit', ctypes.c_uint)]
info = Info()
assert ctypes.CDLL(None).sysinfo(ctypes.byref(info)) == 0
assert info.totalram * info.mem_unit == int(sys.argv[1])
'''
        for memory, expected in (
            ("512m", 512 * 1024**2), ("1.5GB", 3 * 1024**3 // 2),
            ("4294967296", 4 * 1024**3), ("1t", 1024**4), ("0", 0),
        ):
            with self.subTest(memory=memory):
                result = self.guarded(code, expected, env_extra={"OPENCODE_GUARD_MEMORY": memory})
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_guard_memory_fails_startup(self):
        for memory in ("", "1qq", "-1", "1e9999", "18446744073709551616", "99999p"):
            with self.subTest(memory=memory):
                result = self.guarded("raise AssertionError('workload started')", env_extra={"OPENCODE_GUARD_MEMORY": memory})
                self.assertEqual(result.returncode, 1)
                self.assertIn("invalid OPENCODE_GUARD_MEMORY", result.stderr)

    def test_open_flags_umask_and_directory_descriptors(self):
        result = self.guarded('''import os, stat
os.mkdir('sub')
directory = os.open('sub', os.O_RDONLY | os.O_DIRECTORY)
os.umask(0o077)
fd = os.open('private', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666, dir_fd=directory)
os.write(fd, b'hello')
os.close(fd)
assert stat.S_IMODE(os.stat('sub/private').st_mode) == 0o600
try:
    os.open('private', os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=directory)
except FileExistsError:
    pass
else:
    raise AssertionError('O_EXCL lost')
os.symlink('private', 'sub/link')
try:
    os.open('link', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
except OSError:
    pass
else:
    raise AssertionError('O_NOFOLLOW lost')
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sensitive_dirfd_open_is_denied(self):
        (self.base / "alias").symlink_to("/proc/cmdline")
        result = self.guarded('''import os
directory = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
try:
    os.open('alias', os.O_RDONLY, dir_fd=directory)
except PermissionError:
    pass
else:
    raise AssertionError('directory descriptor bypass')
finally:
    os.close(directory)
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_proc_fd_magic_link_is_not_followed(self):
        result = self.guarded('''import errno, os
fd = os.open('regular-file', os.O_CREAT | os.O_RDWR, 0o600)
try:
    os.write(fd, b'allowed filesystem target')
    for path in (f'/proc/{os.getpid()}/fd/{fd}', f'/proc/self/fd/{fd}',
                 f'/proc/thread-self/fd/{fd}', f'/dev/fd/{fd}'):
        try:
            os.open(path, os.O_RDONLY)
        except OSError as e:
            # Self shortcuts resolve in the broker, where this fd may not exist.
            allowed = (errno.ELOOP, errno.EACCES)
            if path != f'/proc/{os.getpid()}/fd/{fd}':
                allowed += (errno.ENOENT,)
            assert e.errno in allowed, (path, e)
        else:
            raise AssertionError('proc fd magic link was followed: ' + path)
finally:
    os.close(fd)
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fifo_blocking_opens_fail_and_normal_io_continues(self):
        result = self.guarded('''import errno, os
os.mkfifo('pipe')
for flags in (os.O_RDONLY, os.O_WRONLY):
    try:
        os.open('pipe', flags)
    except OSError as e:
        assert e.errno in (errno.EACCES, errno.EPERM, errno.ENXIO), e
    else:
        raise AssertionError('FIFO opened')
with open('normal', 'w') as f:
    f.write('still responsive')
assert open('normal').read() == 'still responsive'
''', timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_nonblocking_flags_are_preserved_for_regular_files(self):
        result = self.guarded('''import fcntl, os
fd = os.open('normal', os.O_CREAT | os.O_RDONLY | os.O_NONBLOCK, 0o600)
assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK
os.close(fd)
fd = os.open('normal', os.O_RDONLY)
assert not fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK
os.close(fd)
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_openat2_resolve_flags_and_cloexec_are_preserved(self):
        result = self.guarded('''import ctypes, errno, os
class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64),
                ('resolve', ctypes.c_uint64)]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
os.mkdir('sub')
directory = os.open('sub', os.O_RDONLY | os.O_DIRECTORY)
how = OpenHow(os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, 0o600, 0x08)
fd = libc.syscall(437, directory, b'created', ctypes.byref(how), ctypes.sizeof(how))
assert fd >= 0, OSError(ctypes.get_errno(), 'openat2 create failed')
assert not os.get_inheritable(fd)
os.write(fd, b'created safely')
os.close(fd)
how.flags = os.O_RDONLY
how.mode = 0
fd = libc.syscall(437, directory, b'../outside', ctypes.byref(how), ctypes.sizeof(how))
assert fd == -1 and ctypes.get_errno() == errno.EXDEV, ctypes.get_errno()
os.close(directory)
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_openat2_in_root_uses_caller_directory(self):
        result = self.guarded('''import ctypes, errno, os
class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64),
                ('resolve', ctypes.c_uint64)]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
os.mkdir('root')
open('root/content', 'w').write('rooted')
os.symlink('/content', 'root/link')
directory = os.open('root', os.O_PATH | os.O_DIRECTORY)
how = OpenHow(os.O_RDONLY | os.O_CLOEXEC, 0, 0x10) # RESOLVE_IN_ROOT
def opened(base, path):
    return libc.syscall(437, base, path, ctypes.byref(how), ctypes.sizeof(how))
for path in (b'content', b'/content', b'../content', b'/../content', b'/link'):
    fd = opened(directory, path)
    assert fd >= 0, (path, ctypes.get_errno())
    assert os.read(fd, 32) == b'rooted'
    assert not os.get_inheritable(fd)
    os.close(fd)
assert opened(-1, b'/content') == -1 and ctypes.get_errno() == errno.EBADF
os.chdir('root')
fd = opened(-100, b'/content') # AT_FDCWD must use the caller's cwd
assert fd >= 0, ctypes.get_errno()
assert os.read(fd, 32) == b'rooted'
os.close(fd)
proc = os.open('/proc', os.O_PATH | os.O_DIRECTORY)
assert opened(proc, b'/cmdline') == -1 and ctypes.get_errno() == errno.EACCES
os.close(proc)
os.close(directory)
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_opath_handles_allow_metadata_but_not_content(self):
        result = self.guarded('''import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
open('normal', 'w').write('unchanged')
paths = ('normal', '/proc/cmdline', '/sys', '/sys/fs/cgroup')
for path in paths:
    flags = os.O_PATH | os.O_CLOEXEC | os.O_RDWR | os.O_TRUNC
    # Exercise both legacy open (x86-64 only) and openat, without libc wrappers.
    calls = [(257 if os.uname().machine == 'x86_64' else 56,
              -100, os.fsencode(path), flags, 0)]
    if os.uname().machine == 'x86_64':
        calls.append((2, os.fsencode(path), flags, 0))
    for args in calls:
        fd = libc.syscall(*args)
        assert fd >= 0, (path, ctypes.get_errno())
        assert os.fstat(fd) == os.stat(path)
        assert not os.get_inheritable(fd)
        for operation in (lambda: os.read(fd, 1), lambda: os.write(fd, b'x')):
            try:
                operation()
            except OSError as e:
                assert e.errno == errno.EBADF, e
            else:
                raise AssertionError('O_PATH content access')
        os.close(fd)
assert open('normal').read() == 'unchanged'
for path, child in (('/proc', 'cmdline'), ('/sys', 'kernel'), ('/sys/fs/cgroup', '.')):
    directory = os.open(path, os.O_PATH | os.O_DIRECTORY)
    os.symlink(path, 'alias')
    for name, base in ((child, directory), ('alias/' + child, None),
                       (f'/proc/{os.getpid()}/fd/{directory}/' + child, None)):
        try:
            os.open(name, os.O_RDONLY, dir_fd=base)
        except OSError as e:
            assert e.errno in (errno.EACCES, errno.ELOOP), (name, e)
        else:
            raise AssertionError('O_PATH directory content bypass: ' + name)
    os.unlink('alias')
    os.close(directory)
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_openat2_opath_reports_enosys_for_fallback(self):
        result = self.guarded('''import ctypes, errno, os
class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64),
                ('resolve', ctypes.c_uint64)]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
how = OpenHow(os.O_PATH | os.O_CLOEXEC, 0, 0)
for path in (b'.', b'/proc/cmdline'):
    fd = libc.syscall(437, -100, path, ctypes.byref(how), ctypes.sizeof(how))
    assert fd == -1 and ctypes.get_errno() == errno.ENOSYS, ctypes.get_errno()
    fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    assert os.fstat(fd)
    os.close(fd)
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_later_seccomp_filter_is_denied(self):
        result = self.guarded('''import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(22, 2, 0, 0, 0) == -1
assert ctypes.get_errno() == errno.EPERM
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_exit_status_propagates(self):
        for code in (0, 7):
            result = self.guarded("import sys; sys.exit(int(sys.argv[1]))", code,
                                  timeout=15)
            self.assertEqual(result.returncode, code, result.stderr)

    def test_concurrent_file_opens(self):
        result = self.guarded('''import concurrent.futures
def worker(i):
    for _ in range(50):
        assert open('/etc/os-release').read()
        try:
            open('/proc/cmdline')
        except PermissionError:
            pass
        else:
            raise AssertionError('leak')
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    list(pool.map(worker, range(8)))
''', timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sqlite_wal_persistence(self):
        result = self.guarded('''import sqlite3
for i in range(2):
    db = sqlite3.connect('sessions.db')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS sessions (id INTEGER)')
    db.execute('INSERT INTO sessions VALUES (?)', (i,))
    db.commit()
    assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == i + 1
    db.close()
''')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

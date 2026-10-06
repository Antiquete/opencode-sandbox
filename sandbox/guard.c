/* OpenCode's container entrypoint: hide host details and broker content opens.
 * Metadata-only handles stay native; procfs, sysfs and cgroup content is denied. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NATIVE_ARCH AUDIT_ARCH_X86_64
#define MACHINE "x86_64"
#elif defined(__aarch64__)
#define NATIVE_ARCH AUDIT_ARCH_AARCH64
#define MACHINE "aarch64"
#else
#error "guard supports native x86-64 and aarch64 only"
#endif

/* ---- System-call rules and sandbox identity ---- */

static unsigned long memory_bytes = 4UL * 1024 * 1024 * 1024;

/* Parse runtime memory units without accepting overflow. */
static int parse_memory_limit(void) {
    const char *text = getenv("OPENCODE_GUARD_MEMORY");
    if (!text)
        return 0;
    if (*text < '0' || *text > '9')
        return -1;
    char *end;
    errno = 0;
    long double value = strtold(text, &end);
    if (errno || value < 0)
        return -1;
    while (*end == ' ')
        end++;
    unsigned power = 0;
    if (*end && *end != 'b' && *end != 'B') {
        const char *units = "kKmMgGtTpP", *unit = strchr(units, *end++);
        if (!unit)
            return -1;
        power = (unit - units) / 2 + 1;
    }
    if (*end == 'b' || *end == 'B')
        end++;
    if (*end)
        return -1;
    while (power) {
        value *= 1024;
        power--;
    }
    if (value > ULONG_MAX)
        return -1;
    memory_bytes = (unsigned long)value;
    return 0;
}

/* Ask the guard to check file opens and hide host-only details. */
#define DENY_SYSCALL(n) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
#define BROKER_SYSCALL(n) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)
/* O_PATH is metadata-only. Inspect scalar flags in-kernel, without a race. */
#define OPEN_SYSCALL(n, arg) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[arg])), \
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, O_PATH, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)

static const struct sock_filter filter[] = {
    /* Only handle calls made for this processor type. */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef __x86_64__
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
#endif
    /* Do not let the command replace this filter. */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 4),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    DENY_SYSCALL(seccomp),
    DENY_SYSCALL(io_uring_setup),
    DENY_SYSCALL(io_uring_enter),
    DENY_SYSCALL(io_uring_register),
    DENY_SYSCALL(ptrace),
    DENY_SYSCALL(process_vm_readv),
    DENY_SYSCALL(process_vm_writev),
    DENY_SYSCALL(pidfd_getfd),
    DENY_SYSCALL(open_by_handle_at),
    DENY_SYSCALL(name_to_handle_at),
    DENY_SYSCALL(mount),
    DENY_SYSCALL(umount2),
    DENY_SYSCALL(move_mount),
    DENY_SYSCALL(open_tree),
    DENY_SYSCALL(fsopen),
    DENY_SYSCALL(fsconfig),
    DENY_SYSCALL(fsmount),
    DENY_SYSCALL(fspick),
    DENY_SYSCALL(mount_setattr),
    DENY_SYSCALL(chroot),
    DENY_SYSCALL(pivot_root),
    DENY_SYSCALL(unshare),
    DENY_SYSCALL(setns),
    DENY_SYSCALL(bpf),
    DENY_SYSCALL(perf_event_open),
    DENY_SYSCALL(syslog),
#ifdef __NR_open
    OPEN_SYSCALL(open, 1),
#endif
#ifdef __NR_creat
    BROKER_SYSCALL(creat),
#endif
    OPEN_SYSCALL(openat, 2),
    BROKER_SYSCALL(openat2),
    BROKER_SYSCALL(uname),
    BROKER_SYSCALL(sysinfo),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

/* ---- Read the command's request and process details ---- */

/* Check that a file request is still current. */
static int valid(int listener, uint64_t id) {
    return ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

/* Copy data to or from the command; return an errno on failure. */
static int target_memory(pid_t pid, uint64_t addr, void *buf, size_t len, int to_target) {
    struct iovec local = {buf, len}, remote = {(void *)(uintptr_t)addr, len};
    ssize_t n = syscall(to_target ? SYS_process_vm_writev : SYS_process_vm_readv,
                        pid, &local, 1, &remote, 1, 0);
    return n == (ssize_t)len ? 0 : EFAULT;
}

/* Safely copy a file name from the command. */
static int target_path(pid_t pid, uint64_t addr, char out[4096]) {
    size_t pos = 0;
    while (pos < 4096) {
        size_t n = 256 - ((addr + pos) & 255);
        if (n > 4096 - pos)
            n = 4096 - pos;
        if (target_memory(pid, addr + pos, out + pos, n, 0))
            return EFAULT;
        if (memchr(out + pos, 0, n))
            return 0;
        pos += n;
    }
    return ENAMETOOLONG;
}

/* Only file creation needs the caller's umask. */
static int target_umask(pid_t tid) {
    char name[80], line[256];
    snprintf(name, sizeof(name), "/proc/%d/status", tid);
    FILE *file = fopen(name, "re");
    if (!file)
        return -1;
    unsigned mask = 0;
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if ((found = sscanf(line, "Umask: %o", &mask)) == 1)
            break;
    }
    fclose(file);
    return found == 1 ? (int)mask : -1;
}

/* Check the opened file itself, not just the name used to reach it. */
static int check_open(int fd) {
    struct stat file;
    struct statfs fs;
    if (fstat(fd, &file) || S_ISFIFO(file.st_mode) || fstatfs(fd, &fs))
        return 0;
    return fs.f_type != SYSFS_MAGIC && fs.f_type != PROC_SUPER_MAGIC &&
           fs.f_type != CGROUP_SUPER_MAGIC && fs.f_type != CGROUP2_SUPER_MAGIC;
}

/* ---- Mediating file opens ---- */

/* Copy arguments, pin the base, open and check the actual file, then inject it.
 * Return zero once ADDFD has replied to the caller, or an errno to send back. */
static int emulate_open(const struct seccomp_notif *req, int listener) {
    uint64_t ptr = req->data.args[1];
    int dir = (int)req->data.args[0];
    struct open_how how = {.flags = (unsigned int)req->data.args[2],
                           .mode = (mode_t)req->data.args[3]};
#ifdef __NR_open
    if (req->data.nr == (uint32_t)__NR_open) {
        ptr = req->data.args[0];
        dir = AT_FDCWD;
        how.flags = (unsigned int)req->data.args[1];
        how.mode = (mode_t)req->data.args[2];
    }
#endif
#ifdef __NR_creat
    if (req->data.nr == (uint32_t)__NR_creat) {
        ptr = req->data.args[0];
        dir = AT_FDCWD;
        how.flags = O_CREAT | O_WRONLY | O_TRUNC;
        how.mode = (mode_t)req->data.args[1];
    }
#endif
    if (req->data.nr == (uint32_t)__NR_openat2) {
        if (req->data.args[3] != sizeof(how))
            return EINVAL;
        if (target_memory(req->pid, req->data.args[2], &how, sizeof(how), 0))
            return EFAULT;
    } else {
        how.mode &= 07777;
        if (!(how.flags & O_CREAT) && (how.flags & O_TMPFILE) != O_TMPFILE)
            how.mode = 0;
    }
    /* ADDFD cannot transfer O_PATH; pointer-based flags cannot safely CONTINUE.
     * Let callers fall back to open/openat for metadata-only handles. */
    if (how.flags & O_PATH)
        return ENOSYS;
    int requested_nonblock = !!(how.flags & O_NONBLOCK);
    char path[4096];
    int err = target_path(req->pid, ptr, path);
    if (err)
        return err;
    if (!valid(listener, req->id))
        return ESRCH;
    int mask = 077;
    if ((how.flags & O_CREAT) || (how.flags & O_TMPFILE) == O_TMPFILE) {
        mask = target_umask(req->pid);
        if (mask < 0)
            return EACCES;
    }
    int base = AT_FDCWD;
    /* IN_ROOT uses dirfd even for absolute paths. Pin it before resolving. */
    if (path[0] != '/' || (how.resolve & RESOLVE_IN_ROOT)) {
        char procname[80];
        if (dir == AT_FDCWD)
            snprintf(procname, sizeof(procname), "/proc/%d/cwd", req->pid);
        else
            snprintf(procname, sizeof(procname), "/proc/%d/fd/%d", req->pid, dir);
        base = open(procname, O_PATH | O_CLOEXEC);
        if (base < 0)
            return EBADF;
    }
    /* No proc magic-link shortcuts, and no FIFO may stall the broker. */
    how.resolve |= RESOLVE_NO_MAGICLINKS;
    how.flags |= O_NONBLOCK;
    umask(mask);
    int opened = syscall(SYS_openat2, base, path, &how, sizeof(how));
    err = errno;
    umask(077);
    if (base != AT_FDCWD)
        close(base);
    if (opened < 0)
        return err;
    err = EACCES;
    if (!valid(listener, req->id) || !check_open(opened))
        goto done;
    if (!requested_nonblock) {
        int flags = fcntl(opened, F_GETFL);
        if (flags < 0 || fcntl(opened, F_SETFL, flags & ~O_NONBLOCK)) {
            err = errno;
            goto done;
        }
    }
    struct seccomp_notif_addfd add = {
        .id = req->id,
        .flags = SECCOMP_ADDFD_FLAG_SEND,
        .srcfd = opened,
        .newfd_flags = how.flags & O_CLOEXEC,
    };
    err = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add) < 0 ? errno : 0;
done:
    close(opened);
    return err;
}

/* ---- Start the command and handle its requests ---- */

static volatile sig_atomic_t finished;
static void child_done(int sig) {
    (void)sig;
    finished = 1;
}
static volatile pid_t target_pid;
static void forward_signal(int sig) {
    if (target_pid > 0)
        kill(target_pid, sig);
}

int main(int argc, char **argv) {
    const char *sandbox = getenv("OPENCODE_SANDBOX");
    if (strcmp(argv[0], "/opt/opencode-sandbox/guard") ||
        !sandbox || strcmp(sandbox, "1")) {
        fprintf(stderr, "guard: run through opencode-sandbox\n");
        return 1;
    }
    umask(077);
    if (argc < 2) {
        fprintf(stderr, "guard: missing command placeholder\n");
        return 1;
    }
    if (parse_memory_limit()) {
        fprintf(stderr, "guard: invalid OPENCODE_GUARD_MEMORY\n");
        return 1;
    }
    struct seccomp_notif_sizes sizes;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes)) {
        perror("guard: seccomp notifications required");
        return 1;
    }
    struct seccomp_notif *req = calloc(1, sizes.seccomp_notif);
    struct seccomp_notif_resp *resp = calloc(1, sizes.seccomp_notif_resp);
    if (!req || !resp)
        return 1;
    int sock[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sock))
        return 1;
    /* Both sides inherit the message layout for the one listener transfer. */
    char data = 0, control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = {&data, 1};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = control,
                         .msg_controllen = sizeof(control)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    struct sigaction action = {.sa_handler = child_done};
    sigemptyset(&action.sa_mask);
    sigaction(SIGCHLD, &action, NULL);
    pid_t supervisor = getpid(), child = fork();
    if (child < 0)
        return 1;
    if (!child) {
        /* The child installs the filter, then starts OpenCode. */
        close(sock[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != supervisor)
            _exit(125);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
            _exit(125);
        struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]),
                                     .filter = (struct sock_filter *)filter};
        int listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                               SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
        if (listener < 0) {
            perror("guard: cannot install filter");
            _exit(125);
        }
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &listener, sizeof(listener));
        if (sendmsg(sock[1], &msg, 0) != 1)
            _exit(125);
        close(listener);
        close(sock[1]);
        execvp("opencode", &argv[1]);
        perror("guard: exec");
        _exit(127);
    }
    close(sock[1]);
    target_pid = child;
    action.sa_handler = forward_signal;
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH};
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
        sigaction(signals[i], &action, NULL);
    int listener = -1;
    if (recvmsg(sock[0], &msg, MSG_CMSG_CLOEXEC) == 1 &&
        msg.msg_controllen >= CMSG_LEN(sizeof(int)) &&
        c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
        c->cmsg_len == CMSG_LEN(sizeof(int)))
        memcpy(&listener, CMSG_DATA(c), sizeof(listener));
    close(sock[0]);
    if (listener < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        fprintf(stderr, "guard: startup failed\n");
        return 125;
    }
    struct timespec boot_time;
    clock_gettime(CLOCK_MONOTONIC, &boot_time);
    int status = 0;
    for (;;) {
        if (finished && waitpid(child, &status, WNOHANG) == child)
            break;
        struct pollfd pending = {.fd = listener, .events = POLLIN};
        int ready = poll(&pending, 1, 200);
        if (ready < 0 && errno != EINTR) {
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            break;
        }
        if (ready <= 0 || !(pending.revents & POLLIN))
            continue;
        /* Clear old data before reading the next request. */
        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, req)) {
            if (errno == EINTR || errno == ENOENT)
                continue;
            perror("guard: receive");
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            break;
        }
        memset(resp, 0, sizes.seccomp_notif_resp);
        resp->id = req->id;
        if (!valid(listener, req->id))
            continue;
        if (req->data.nr == (uint32_t)__NR_uname) {
            struct utsname info = {.sysname = "Linux",
                                   .nodename = "opencode",
                                   .release = "6.1.0-sandbox",
                                   .version = "#1 SMP",
                                   .machine = MACHINE,
                                   .domainname = "(none)"};
            resp->error = -target_memory(req->pid, req->data.args[0], &info, sizeof(info), 1);
        } else if (req->data.nr == (uint32_t)__NR_sysinfo) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            struct sysinfo info = {.uptime = now.tv_sec - boot_time.tv_sec,
                                   .totalram = memory_bytes,
                                   .freeram = memory_bytes,
                                   .procs = 1,
                                   .mem_unit = 1};
            resp->error = -target_memory(req->pid, req->data.args[0], &info, sizeof(info), 1);
        } else {
            resp->error = -emulate_open(req, listener);
            if (!resp->error)
                continue;
        }
        if (valid(listener, req->id) &&
            ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, resp) && errno != ENOENT)
            fprintf(stderr, "guard: reply failed: %s\n", strerror(errno));
    }
    close(listener);
    free(req);
    free(resp);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

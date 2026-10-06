/* Runs a command while hiding host details and checking every opened file.
 * Unclear or unsafe files are denied. */
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

/* Keep this size exact; a larger reply can overwrite the command's memory. */
struct kernel_sysinfo {
    long          uptime;
    unsigned long loads[3];
    unsigned long totalram;
    unsigned long freeram;
    unsigned long sharedram;
    unsigned long bufferram;
    unsigned long totalswap;
    unsigned long freeswap;
    unsigned short procs;
    unsigned short pad;
    unsigned long totalhigh;
    unsigned long freehigh;
    unsigned int  mem_unit;
    char          tail[4];
};

static unsigned long memory_bytes = 4UL * 1024 * 1024 * 1024;

/* Parse the launcher's validated memory limit without accepting overflow. */
static int parse_memory_limit(void) {
    const char *text = getenv("OPENCODE_GUARD_MEMORY");
    if (!text)
        return 0;
    if (*text < '1' || *text > '9')
        return -1;
    unsigned long value = 0;
    unsigned digits = 0;
    while (*text >= '0' && *text <= '9') {
        if (digits == 9)
            return -1;
        value = value * 10 + (unsigned)(*text - '0');
        digits++;
        text++;
    }
    unsigned long multiplier = 1;
    if (*text) {
        switch (*text++) {
        case 'k':
        case 'K':
            multiplier = 1024UL;
            break;
        case 'm':
        case 'M':
            multiplier = 1024UL * 1024;
            break;
        case 'g':
        case 'G':
            multiplier = 1024UL * 1024 * 1024;
            break;
        default:
            return -1;
        }
        if (*text)
            return -1;
    }
    if (value > ULONG_MAX / multiplier)
        return -1;
    memory_bytes = value * multiplier;
    return 0;
}

/* Ask the guard to check file opens and hide host-only details. */
#define DENY_SYSCALL(n) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
#define BROKER_SYSCALL(n) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), \
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
    BROKER_SYSCALL(open),
#endif
#ifdef __NR_creat
    BROKER_SYSCALL(creat),
#endif
    BROKER_SYSCALL(openat),
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

/* Copy data to or from the command. */
static int target_memory(pid_t pid, uint64_t addr, void *buf, size_t len, int to_target) {
    struct iovec local = {buf, len}, remote = {(void *)(uintptr_t)addr, len};
    ssize_t n = syscall(to_target ? SYS_process_vm_writev : SYS_process_vm_readv,
                        pid, &local, 1, &remote, 1, 0);
    return n == (ssize_t)len ? 0 : -1;
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

/* Get the process id and file-creation setting for the request. */
static int target_info(pid_t tid, pid_t *tgid, unsigned *mask) {
    char name[80], line[256];
    snprintf(name, sizeof(name), "/proc/%d/status", tid);
    FILE *file = fopen(name, "re");
    if (!file)
        return -1;
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "Tgid: %d", tgid) == 1)
            found |= 1;
        if (sscanf(line, "Umask: %o", mask) == 1)
            found |= 2;
    }
    fclose(file);
    return found == 3 ? 0 : -1;
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

/* Decode open/openat/creat/openat2 arguments into a path pointer, base
 * descriptor, and flags. Returns 1 for openat2, 0 otherwise, -1 on error. */
static int decode_open(const struct seccomp_notif *req, uint64_t *ptr, int *dir,
                       struct open_how *how) {
    memset(how, 0, sizeof(*how));
    *ptr = req->data.args[1];
    *dir = (int)req->data.args[0];
    how->flags = req->data.args[2];
    how->mode = req->data.args[3];
#ifdef __NR_open
    if (req->data.nr == (uint32_t)__NR_open) {
        *ptr = req->data.args[0];
        *dir = AT_FDCWD;
        how->flags = req->data.args[1];
        how->mode = req->data.args[2];
    }
#endif
#ifdef __NR_creat
    if (req->data.nr == (uint32_t)__NR_creat) {
        *ptr = req->data.args[0];
        *dir = AT_FDCWD;
        how->flags = O_CREAT | O_WRONLY | O_TRUNC;
        how->mode = req->data.args[1];
    }
#endif
    if (req->data.nr != (uint32_t)__NR_openat2)
        return 0;
    if (req->data.args[3] != sizeof(*how)) {
        errno = EINVAL;
        return -1;
    }
    if (target_memory(req->pid, req->data.args[2], how, sizeof(*how), 0)) {
        errno = EFAULT;
        return -1;
    }
    /* This path option is not supported. */
    if (how->resolve & RESOLVE_IN_ROOT) {
        errno = EOPNOTSUPP;
        return -1;
    }
    return 1;
}

/* Make process and descriptor shortcuts point to the caller. */
static void translate_open_path(const char *path, pid_t tid, pid_t *tgid,
                                char translated[4096]) {
    const char *suffix = NULL;
    if (!strcmp(path, "/proc/net"))
        suffix = "net";
    else if (!strncmp(path, "/proc/net/", 10))
        suffix = path + 6;
    else if (!strncmp(path, "/proc/self/", 11))
        suffix = path + 11;
    else if (!strncmp(path, "/proc/thread-self/", 18)) {
        suffix = path + 18;
        *tgid = tid;
    }
    if (!strncmp(path, "/dev/fd/", 8)) {
        /* Keep the translated name within its buffer. */
        snprintf(translated, 4096, "/proc/%d/fd/%.4000s", tid, path + 8);
    } else if (!strcmp(path, "/dev/stdin")) {
        snprintf(translated, 4096, "/proc/%d/fd/0", tid);
    } else if (!strcmp(path, "/dev/stdout")) {
        snprintf(translated, 4096, "/proc/%d/fd/1", tid);
    } else if (!strcmp(path, "/dev/stderr")) {
        snprintf(translated, 4096, "/proc/%d/fd/2", tid);
    } else if (suffix) {
        snprintf(translated, 4096, "/proc/%d/%.4000s", *tgid, suffix);
    } else {
        snprintf(translated, 4096, "%s", path);
    }
}

/* Open the translated path under the caller's umask and reply flags. */
static int perform_open(int base, const char *translated, struct open_how *how,
                        int is_openat2, unsigned mask, int *close_exec) {
    if (!is_openat2 && !(how->flags & O_CREAT) &&
        (how->flags & O_TMPFILE) != O_TMPFILE)
        how->mode = 0;
    /* Enforce magic-link denial during the actual open. */
    how->resolve |= RESOLVE_NO_MAGICLINKS;
    /* Prevent a late FIFO from blocking the broker during open. */
    how->flags |= O_NONBLOCK;
    *close_exec = !!(how->flags & O_CLOEXEC);
    umask(mask);
    int opened = syscall(SYS_openat2, base, translated, how, sizeof(*how));
    int saved = errno;
    umask(077);
    if (opened < 0)
        errno = saved;
    return opened;
}

/* Check the file after opening it, when its true target is known. */
static int verify_opened(int listener, uint64_t id, int opened,
                         int requested_nonblock) {
    if (!valid(listener, id) || !check_open(opened)) {
        close(opened);
        errno = EACCES;
        return -1;
    }
    if (!requested_nonblock) {
        int flags = fcntl(opened, F_GETFL);
        if (flags < 0 || fcntl(opened, F_SETFL, flags & ~O_NONBLOCK)) {
            int err = errno;
            close(opened);
            errno = err;
            return -1;
        }
    }
    return 0;
}

/* Open a requested file and return it only if it passes the checks. */
static int emulate_open(const struct seccomp_notif *req, int listener, int *close_exec) {
    uint64_t ptr;
    int dir;
    struct open_how how;
    int is_openat2 = decode_open(req, &ptr, &dir, &how);
    if (is_openat2 < 0)
        return -1;
    /* Do not allow handles that bypass normal file checks. */
    if (how.flags & O_PATH) {
        errno = EOPNOTSUPP;
        return -1;
    }
    int requested_nonblock = !!(how.flags & O_NONBLOCK);
    char path[4096];
    int err = target_path(req->pid, ptr, path);
    if (err) {
        errno = err;
        return -1;
    }
    /* Keep enough room for translated process paths. */
    if (strlen(path) > sizeof(path) - 32) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (!valid(listener, req->id)) {
        errno = ESRCH;
        return -1;
    }
    pid_t tgid;
    unsigned mask;
    if (target_info(req->pid, &tgid, &mask)) {
        errno = EACCES;
        return -1;
    }
    char translated[4096];
    translate_open_path(path, req->pid, &tgid, translated);
    int base = AT_FDCWD;
    if (translated[0] != '/') {
        char procname[80];
        if (dir == AT_FDCWD)
            snprintf(procname, sizeof(procname), "/proc/%d/cwd", req->pid);
        else
            snprintf(procname, sizeof(procname), "/proc/%d/fd/%d", req->pid, dir);
        base = open(procname, O_PATH | O_CLOEXEC);
        if (base < 0) {
            errno = EBADF;
            return -1;
        }
    }
    int opened = perform_open(base, translated, &how, is_openat2, mask, close_exec);
    if (base != AT_FDCWD)
        close(base);
    if (opened < 0)
        return -1;
    if (verify_opened(listener, req->id, opened, requested_nonblock))
        return -1;
    return opened;
}

/* ---- Pass the filter and checked files between processes ---- */

/* Send a file handle to the other process. */
static int send_fd(int sock, int fd) {
    char data = 0, control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = {&data, 1};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = control,
                         .msg_controllen = sizeof(control)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(fd));
    return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

static int receive_fd(int sock) {
    char data, control[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {&data, 1};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = control,
                         .msg_controllen = sizeof(control)};
    if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) != 1)
        return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len != CMSG_LEN(sizeof(int)))
        return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(fd));
    return fd;
}

/* ---- Start the command and handle its requests ---- */

static struct timespec boot_time;

/* Report a fixed sandbox identity instead of the host's. */
static int emulate_uname(const struct seccomp_notif *req) {
    struct utsname info = {.sysname = "Linux",
                           .nodename = "opencode",
                           .release = "6.1.0-sandbox",
                           .version = "#1 SMP",
                           .domainname = "(none)"};
    strncpy(info.machine, MACHINE, sizeof(info.machine) - 1);
    if (target_memory(req->pid, req->data.args[0], &info, sizeof(info), 1)) {
        errno = EFAULT;
        return -1;
    }
    return 0;
}

/* Report the sandbox memory limit and its own uptime. */
static int emulate_sysinfo(const struct seccomp_notif *req) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct kernel_sysinfo info = {
        .uptime = now.tv_sec - boot_time.tv_sec,
        .totalram = memory_bytes,
        .freeram = memory_bytes,
        .procs = 1,
        .mem_unit = 1,
    };
    if (target_memory(req->pid, req->data.args[0], &info, sizeof(info), 1)) {
        errno = EFAULT;
        return -1;
    }
    return 0;
}

/* Give the checked file to the command. */
static int install_fd(int listener, uint64_t id, int opened, int close_exec) {
    struct seccomp_notif_addfd add = {
        .id = id,
        .flags = SECCOMP_ADDFD_FLAG_SEND,
        .srcfd = opened,
        .newfd_flags = close_exec ? O_CLOEXEC : 0,
    };
    int result = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
    int saved = errno;
    close(opened);
    if (result >= 0)
        return 0;
    errno = saved;
    return -1;
}

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
    (void)argc;
    const char *sandbox = getenv("OPENCODE_SANDBOX");
    if (strcmp(argv[0], "/opt/opencode-sandbox/guard") ||
        !sandbox || strcmp(sandbox, "1")) {
        fprintf(stderr, "guard: run through opencode-sandbox\n");
        return 1;
    }
    umask(077);
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
        if (send_fd(sock[1], listener))
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
    int listener = receive_fd(sock[0]);
    close(sock[0]);
    if (listener < 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        fprintf(stderr, "guard: startup failed\n");
        return 125;
    }
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
            resp->error = emulate_uname(req) ? -errno : 0;
        } else if (req->data.nr == (uint32_t)__NR_sysinfo) {
            resp->error = emulate_sysinfo(req) ? -errno : 0;
        } else {
            int close_exec = 0;
            int opened = emulate_open(req, listener, &close_exec);
            if (opened >= 0 && install_fd(listener, req->id, opened, close_exec) == 0)
                continue;
            resp->error = -errno;
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

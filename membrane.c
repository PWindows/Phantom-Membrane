#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/filter.h>

/* ---- Minimal BPF instruction-construction macros (no libbpf) ---- */
#ifndef BPF_PSEUDO_MAP_FD
#define BPF_PSEUDO_MAP_FD 1
#endif

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){ .code = CODE, .dst_reg = DST, .src_reg = SRC, \
                        .off = OFF, .imm = IMM })
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) \
    BPF_RAW_INSN(BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, DST, SRC, OFF, 0)
#define BPF_MOV64_IMM(DST, IMM) \
    BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define BPF_EXIT_INSN() \
    BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
    BPF_RAW_INSN(BPF_JMP | BPF_OP(OP) | BPF_K, DST, 0, OFF, IMM)
#define BPF_EMIT_CALL(FUNC) \
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, FUNC)
#define BPF_LD_MAP_FD(DST, MAP_FD) \
    BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, DST, BPF_PSEUDO_MAP_FD, 0, MAP_FD), \
    BPF_RAW_INSN(0, 0, 0, 0, 0)

/* ---------------- helpers ---------------- */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s\n"
        "  --runtime <mountpoint>  --runtime-src <linux-path>\n"
        "  --server  <mountpoint>  --server-src  <linux-path>\n"
        "  --uuid <server-uuid>    (required for --allow-port)\n"
        "  [--allow-port <port>]   (repeatable)\n"
        "  [--exec <cmd> [args...]]\n",
        prog);
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "membrane: %s exists but is not a directory\n", path);
        return -1;
    }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "membrane: mkdir(%s): %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int do_mount(const char *src, const char *target) {
    if (ensure_dir(target) != 0) return -1;
    if (mount(src, target, NULL, MS_BIND, NULL) == 0) return 0;
    if (errno == EBUSY) return 0;
    fprintf(stderr, "membrane: bind mount(%s -> %s): %s\n",
            src, target, strerror(errno));
    return -1;
}

/* ---------------- BPF port restriction ---------------- */

static int bpf_sys(int cmd, union bpf_attr *attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int bpf_create_map(enum bpf_map_type type, __u32 ks, __u32 vs, __u32 max) {
    union bpf_attr attr = {
        .map_type = type, .key_size = ks, .value_size = vs, .max_entries = max,
    };
    return bpf_sys(BPF_MAP_CREATE, &attr);
}

static int bpf_update_elem(int fd, const void *k, const void *v) {
    union bpf_attr attr = {
        .map_fd = fd, .key = (unsigned long)k, .value = (unsigned long)v,
        .flags = BPF_ANY,
    };
    return bpf_sys(BPF_MAP_UPDATE_ELEM, &attr);
}

static int bpf_load_prog(enum bpf_prog_type type,
                         enum bpf_attach_type eat,
                         const struct bpf_insn *insns,
                         __u32 cnt, const char *lic) {
    static char log[16384];
    union bpf_attr attr = {
        .prog_type = type, .expected_attach_type = eat,
        .insns = (unsigned long)insns, .insn_cnt = cnt,
        .license = (unsigned long)lic,
        .log_buf = (unsigned long)log, .log_size = sizeof(log), .log_level = 1,
    };
    int fd = bpf_sys(BPF_PROG_LOAD, &attr);
    if (fd < 0)
        fprintf(stderr, "membrane: BPF_PROG_LOAD: %s\n%s\n", strerror(errno), log);
    return fd;
}

static int bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type t) {
    union bpf_attr attr = {
        .target_fd = target_fd, .attach_bpf_fd = prog_fd, .attach_type = t,
    };
    return bpf_sys(BPF_PROG_ATTACH, &attr);
}

/*
 * Hand-written BPF program for cgroup/bind4:
 *
 *   r2 = *(u32 *)(r1 + offsetof(struct bpf_sock_addr, user_port))
 *   r1 = map_fd                        ; patched at load time
 *   call bpf_map_lookup_elem
 *   if r0 == 0 goto deny
 *   r0 = 1
 *   exit
 * deny:
 *   r0 = 0
 *   exit
 */
static int setup_port_restriction(const char *uuid, char **ports, int nports) {
    if (nports <= 0) return 0;

    char cg_path[256];
    snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/pw-%s", uuid);
    if (mkdir(cg_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "membrane: mkdir(%s): %s\n", cg_path, strerror(errno));
        return -1;
    }

    int map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u8), 64);
    if (map_fd < 0) {
        fprintf(stderr, "membrane: BPF_MAP_CREATE: %s\n", strerror(errno));
        return -1;
    }

    struct bpf_insn insns[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 24), /* user_port */
        BPF_LD_MAP_FD(BPF_REG_1, 0),
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    /* Patch the map FD into the LD_MAP_FD instruction pair */
    for (size_t i = 0; i + 1 < sizeof(insns) / sizeof(insns[0]); i++) {
        if (insns[i].code == (BPF_LD | BPF_DW | BPF_IMM) &&
            insns[i].src_reg == BPF_PSEUDO_MAP_FD) {
            insns[i + 1].imm = map_fd;
            break;
        }
    }

    int prog_fd = bpf_load_prog(BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                                BPF_CGROUP_INET4_BIND,
                                insns, sizeof(insns) / sizeof(insns[0]), "GPL");
    if (prog_fd < 0) return -1;

    for (int i = 0; i < nports; i++) {
        __u32 key = htonl((__u32)atoi(ports[i]));
        __u8  val = 1;
        if (bpf_update_elem(map_fd, &key, &val) != 0) {
            fprintf(stderr, "membrane: BPF_MAP_UPDATE(%s): %s\n",
                    ports[i], strerror(errno));
            return -1;
        }
    }

    int cg_fd = open(cg_path, O_RDONLY | O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "membrane: open(%s): %s\n", cg_path, strerror(errno));
        return -1;
    }
    if (bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_INET4_BIND) != 0) {
        fprintf(stderr, "membrane: BPF_PROG_ATTACH: %s\n", strerror(errno));
        close(cg_fd);
        return -1;
    }
    close(cg_fd);

    char procs[300];
    snprintf(procs, sizeof(procs), "%s/cgroup.procs", cg_path);
    int pf = open(procs, O_WRONLY);
    if (pf < 0) {
        fprintf(stderr, "membrane: open(%s): %s\n", procs, strerror(errno));
        return -1;
    }
    char pid[16];
    int n = snprintf(pid, sizeof(pid), "%d", getpid());
    if (write(pf, pid, n) != n) {
        fprintf(stderr, "membrane: write(%s): %s\n", procs, strerror(errno));
        close(pf);
        return -1;
    }
    close(pf);

    printf("membrane: port restriction active (%d ports)\n", nports);
    return 0;
}

/* ---------------- main ---------------- */

int main(int argc, char *argv[]) {
    char *runtime = NULL, *runtime_src = NULL;
    char *server = NULL,  *server_src = NULL;
    char *uuid = NULL;
    char *allow_ports[64];
    int nallow = 0;
    char **exec_argv = NULL;
    int exec_argc = 0;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--runtime")     && i+1 < argc) runtime     = argv[++i];
        else if (!strcmp(argv[i], "--runtime-src") && i+1 < argc) runtime_src = argv[++i];
        else if (!strcmp(argv[i], "--server")      && i+1 < argc) server      = argv[++i];
        else if (!strcmp(argv[i], "--server-src")  && i+1 < argc) server_src  = argv[++i];
        else if (!strcmp(argv[i], "--uuid")        && i+1 < argc) uuid        = argv[++i];
        else if (!strcmp(argv[i], "--allow-port")  && i+1 < argc) {
            if (nallow < 64) allow_ports[nallow++] = argv[++i];
        }
        else if (!strcmp(argv[i], "--exec")        && i+1 < argc) {
            exec_argv = &argv[i + 1];
            exec_argc = argc - i - 1;
            break;
        } else {
            fprintf(stderr, "membrane: unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!runtime || !runtime_src || !server || !server_src) {
        usage(argv[0]);
        return 1;
    }

    if (do_mount(runtime_src, runtime) != 0) return 1;
    if (do_mount(server_src, server) != 0) return 1;

    if (exec_argc == 0) return 0;

    if (nallow > 0 && uuid) {
        if (setup_port_restriction(uuid, allow_ports, nallow) != 0) {
            fprintf(stderr, "membrane: port restriction failed\n");
            return 1;
        }
    }

    if (chdir(server) != 0) {
        fprintf(stderr, "membrane: chdir(%s): %s\n", server, strerror(errno));
        return 1;
    }

    char *old_path = getenv("PATH");
    char new_path[8192];
    snprintf(new_path, sizeof(new_path), "%s/bin:%s", runtime, old_path ? old_path : "");
    setenv("PATH", new_path, 1);

    execvp(exec_argv[0], exec_argv);
    fprintf(stderr, "membrane: exec %s: %s\n", exec_argv[0], strerror(errno));
    return 127;
}
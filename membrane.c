#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s\n"
        "  --runtime <mountpoint>  --runtime-src <linux-path>\n"
        "  --server  <mountpoint>  --server-src  <linux-path>\n"
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

int main(int argc, char *argv[]) {
    char *runtime = NULL, *runtime_src = NULL;
    char *server = NULL,  *server_src = NULL;
    char **exec_argv = NULL;
    int exec_argc = 0;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--runtime")     == 0 && i + 1 < argc) runtime     = argv[++i];
        else if (strcmp(argv[i], "--runtime-src") == 0 && i + 1 < argc) runtime_src = argv[++i];
        else if (strcmp(argv[i], "--server")      == 0 && i + 1 < argc) server      = argv[++i];
        else if (strcmp(argv[i], "--server-src")  == 0 && i + 1 < argc) server_src  = argv[++i];
        else if (strcmp(argv[i], "--exec")        == 0 && i + 1 < argc) {
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
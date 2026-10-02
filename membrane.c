#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s\n"
        "  --runtime <mountpoint>  --runtime-src <windows-path>\n"
        "  --server  <mountpoint>  --server-src  <windows-path>\n"
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

/* Fork + exec /init as "mount.drvfs" to perform a real drvfs mount. */
static int do_mount(const char *src, const char *target) {
    if (ensure_dir(target) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "membrane: fork: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        char *argv[] = {
            "mount.drvfs",
            "-t", "drvfs",
            "-o", "metadata,uid=0,gid=0",
            (char *)src,
            (char *)target,
            NULL
        };
        execve("/init", argv, NULL);
        execve("/usr/sbin/mount.drvfs", argv, NULL);
        execve("/sbin/mount.drvfs", argv, NULL);
        fprintf(stderr, "membrane: exec mount.drvfs failed: %s\n", strerror(errno));
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "membrane: waitpid: %s\n", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;

    fprintf(stderr, "membrane: mount(%s -> %s) failed (exit %d)\n",
            src, target, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
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

    /* No command: mount and exit */
    if (exec_argc == 0) return 0;

    /* Prepend <runtime>/bin to PATH so execvp finds java, etc. */
    char *old_path = getenv("PATH");
    char new_path[8192];
    snprintf(new_path, sizeof(new_path), "%s/bin:%s", runtime, old_path ? old_path : "");
    setenv("PATH", new_path, 1);

    /* Exec the game — this replaces membrane's process image.
       Its stdin/stdout/stderr flow back to whatever spawned us (Wings).
       When it exits, the distro has nothing left running and shuts down. */
    execvp(exec_argv[0], exec_argv);
    fprintf(stderr, "membrane: exec %s: %s\n", exec_argv[0], strerror(errno));
    return 127;
}
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
        "  --server  <mountpoint>  --server-src  <windows-path>\n",
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

/* Fork+exec /init as mount.drvfs to perform a proper drvfs mount */
static int do_mount(const char *src, const char *target) {
    if (ensure_dir(target) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "membrane: fork: %s\n", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* Child: exec /init as mount.drvfs */
        char *argv[] = {
            "mount.drvfs",
            "-t", "drvfs",
            "-o", "metadata,uid=0,gid=0",
            (char *)src,
            (char *)target,
            NULL
        };
        execve("/init", argv, NULL);

        /* If /init doesn't exist, try the well-known symlink locations */
        execve("/usr/sbin/mount.drvfs", argv, NULL);
        execve("/sbin/mount.drvfs", argv, NULL);

        fprintf(stderr, "membrane: exec mount.drvfs: %s\n", strerror(errno));
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;

    /* Already mounted? */
    if (access(target, F_OK) == 0) {
        struct stat st;
        if (stat(target, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    }

    fprintf(stderr, "membrane: drvfs mount failed for %s -> %s (exit %d)\n",
            src, target, WEXITSTATUS(status));
    return -1;
}

int main(int argc, char *argv[]) {
    char *runtime = NULL, *runtime_src = NULL;
    char *server = NULL,  *server_src = NULL;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--runtime")     == 0 && i + 1 < argc) runtime     = argv[++i];
        else if (strcmp(argv[i], "--runtime-src") == 0 && i + 1 < argc) runtime_src = argv[++i];
        else if (strcmp(argv[i], "--server")      == 0 && i + 1 < argc) server      = argv[++i];
        else if (strcmp(argv[i], "--server-src")  == 0 && i + 1 < argc) server_src  = argv[++i];
    }

    if (!runtime || !runtime_src || !server || !server_src) {
        usage(argv[0]);
        return 1;
    }

    if (do_mount(runtime_src, runtime) != 0) return 1;
    if (do_mount(server_src, server)   != 0) return 1;

    printf("Phantom Membrane active.\n");
    printf("  Runtime: %s -> %s\n", runtime_src, runtime);
    printf("  Server:  %s -> %s\n", server_src, server);
    fflush(stdout);

    while (1) pause();
    return 0;
}
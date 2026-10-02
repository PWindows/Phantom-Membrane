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
        "  --runtime <mountpoint>  --runtime-src <windows-path>\n"
        "  --server  <mountpoint>  --server-src  <windows-path>\n",
        prog);
}

/* drvfs wants backslash Windows paths (D:\foo\bar), not D:/foo/bar */
static void to_backslashes(char *s) {
    for (; *s; s++) if (*s == '/') *s = '\\';
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

static int do_mount(char *src, const char *target) {
    if (ensure_dir(target) != 0) return -1;

    to_backslashes(src);

    if (mount(src, target, "drvfs", 0, "metadata") == 0) return 0;
    if (errno == EBUSY) return 0;

    if (mount(src, target, "drvfs", 0, NULL) == 0) return 0;
    if (errno == EBUSY) return 0;

    fprintf(stderr, "membrane: mount(%s -> %s): %s\n",
            src, target, strerror(errno));
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

    /* Duplicate so we can mutate in place (to_backslashes modifies the string) */
    char *rs = strdup(runtime_src);
    char *ss = strdup(server_src);

    if (do_mount(rs, runtime) != 0) return 1;
    if (do_mount(ss, server)  != 0) return 1;

    printf("Phantom Membrane active.\n");
    printf("  Runtime: %s -> %s\n", rs, runtime);
    printf("  Server:  %s -> %s\n", ss, server);
    fflush(stdout);

    while (1) pause();
    return 0;
}
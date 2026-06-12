#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    char *runtime_mountpoint = NULL;
    char *server_mountpoint = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--runtime") == 0 && i + 1 < argc) {
            runtime_mountpoint = argv[++i];
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server_mountpoint = argv[++i];
        }
    }

    if (!runtime_mountpoint || !server_mountpoint) {
        fprintf(stderr, "Usage: %s --runtime <path> --server <path>\n", argv[0]);
        return 1;
    }

    if (access(runtime_mountpoint, F_OK) != 0) {
        fprintf(stderr, "Runtime mount point %s does not exist\n", runtime_mountpoint);
        return 1;
    }

    if (access(server_mountpoint, F_OK) != 0) {
        fprintf(stderr, "Server mount point %s does not exist\n", server_mountpoint);
        return 1;
    }

    printf("Phantom Membrane active. Runtime: %s, Server: %s\n", runtime_mountpoint, server_mountpoint);
    fflush(stdout);

    // Keep the distro alive forever
    while (1) {
        pause();
    }

    return 0;
}
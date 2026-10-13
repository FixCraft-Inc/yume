#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int armed;

int rename(const char *from, const char *to) {
    static int (*real_rename)(const char *, const char *);
    if (real_rename == NULL)
        real_rename = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "rename");
    // YUME_RENAME_FAILURE_TARGET makes the matching rename itself fail.
    const char *refused = getenv("YUME_RENAME_FAILURE_TARGET");
    if (refused != NULL && strstr(to, refused) != NULL) {
        errno = EIO;
        return -1;
    }
    const int result = real_rename(from, to);
    const char *target = getenv("YUME_FSYNC_FAILURE_TARGET");
    if (result == 0 && target != NULL && strstr(to, target) != NULL)
        armed = 1;
    return result;
}

int renameat2(int from_dir, const char *from, int to_dir, const char *to,
              unsigned int flags) {
    static int (*real_renameat2)(int, const char *, int, const char *, unsigned int);
    if (real_renameat2 == NULL)
        real_renameat2 = (int (*)(int, const char *, int, const char *, unsigned int))
            dlsym(RTLD_NEXT, "renameat2");
    const int result = real_renameat2(from_dir, from, to_dir, to, flags);
    const char *target = getenv("YUME_FSYNC_FAILURE_TARGET");
    if (result == 0 && target != NULL && strstr(to, target) != NULL)
        armed = 1;
    return result;
}

int fsync(int fd) {
    static int (*real_fsync)(int);
    if (real_fsync == NULL)
        real_fsync = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    struct stat status;
    if (armed && fstat(fd, &status) == 0 && S_ISDIR(status.st_mode)) {
        errno = EIO;
        return -1;
    }
    return real_fsync(fd);
}

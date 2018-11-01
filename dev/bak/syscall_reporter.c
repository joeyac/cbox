//
// Created by xjw on 10/28/18.
//
#include "subdir/config.h"
#include "subdir/seccomp-bpf.h"
#include "subdir/syscall-reporter.h"

static struct sock_filter filter[] = {
        {0x0020, 0x00, 0x00, 0x00000004},
        {0x0015, 0x00, 0x1b, 0xc000003e},
        {0x0020, 0x00, 0x00, 0x00000000},
        {0x0035, 0x19, 0x00, 0x40000000},
        {0x0015, 0x17, 0x00, 0x00000000},
        {0x0015, 0x16, 0x00, 0x00000003},
        {0x0015, 0x15, 0x00, 0x00000005},
        {0x0015, 0x14, 0x00, 0x00000008},
        {0x0015, 0x13, 0x00, 0x00000009},
        {0x0015, 0x12, 0x00, 0x0000000a},
        {0x0015, 0x11, 0x00, 0x0000000b},
        {0x0015, 0x10, 0x00, 0x0000000c},
        {0x0015, 0x0f, 0x00, 0x00000015},
        {0x0015, 0x0e, 0x00, 0x0000003b},
        {0x0015, 0x0d, 0x00, 0x00000050},
        {0x0015, 0x0c, 0x00, 0x0000009e},
        {0x0015, 0x0b, 0x00, 0x000000e7},
        {0x0015, 0x00, 0x04, 0x00000001},
        {0x0020, 0x00, 0x00, 0x00000014},
        {0x0035, 0x00, 0x08, 0x00000000},
        {0x0020, 0x00, 0x00, 0x00000010},
        {0x0025, 0x05, 0x06, 0x00000002},
        {0x0015, 0x00, 0x04, 0x00000002},
        {0x0020, 0x00, 0x00, 0x00000014},
        {0x0015, 0x00, 0x02, 0x00000000},
        {0x0020, 0x00, 0x00, 0x00000010},
        {0x0015, 0x01, 0x00, 0x00401a84},
        {0x0006, 0x00, 0x00, 0x00030000},
        {0x0006, 0x00, 0x00, 0x7fff0000},
        {0x0006, 0x00, 0x00, 0x00000000},
};

static int install_syscall_filter() {
    struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
            .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        goto failed;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        goto failed;
    }
    return 0;

    failed:
    if (errno == EINVAL)
        fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
    return 1;
}

void func() {
    FILE *f = fopen("public.txt", "r");
    char *x = malloc(100 * sizeof(char));
    fscanf(f, "%s", x);
    printf("public read: %s\n", x);
    free(x);
    fclose(f);
}

int main() {
    if (install_syscall_reporter()) {
        printf("install reporter failed");
        return 1;
    }
    if (install_syscall_filter()) {
        printf("install syscall failed");
        return 1;
    }
    func();
    return 0;
}
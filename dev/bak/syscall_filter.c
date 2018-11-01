//
// Created by xjw on 10/27/18.
//
#define _GNU_SOURCE 1
#include <seccomp.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "subdir/config.h"
#include "subdir/seccomp-bpf.h"
#include "subdir/syscall-reporter.h"

void export_scmp_filter() {
//    FILE *f = fopen("bpf.out", "w");
//    int sfd = dup(STDOUT_FILENO);
//    if (-1 == dup2(fileno(f), STDOUT_FILENO) ) {
//        printf("can't redirect fd error\n");
//        exit(1);
//    }

    scmp_filter_ctx ctx = NULL;
    ctx = seccomp_init(SCMP_ACT_TRAP);  // 不符合规则的调用直接kill

    // 文件读写打开关闭操作
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, STDIN_FILENO));

//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_LE, STDERR_FILENO));

//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A0(SCMP_CMP_EQ, fileno(stdin)));
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t) "public.txt"));

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);

    // 获取文件信息
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);

    // 将文件或设备映射或取消映射到内存中
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    // 设置内存区域的保护
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);

    // 更改数据段大小
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

    // 测试文件访问权限
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);

    // 设置特定于架构的线程状态
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);

    // 重新定位read/write文件的偏移量
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);

    // 终止调用线程且终止调用进程线程组中的所有线程
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    // python:
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    // 以上为一个最基础的hello world程序所需系统调用

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);

    seccomp_load(ctx);

//    seccomp_export_bpf(ctx, STDOUT_FILENO);

    seccomp_release(ctx);
}

void openPublic() {
    FILE *f = fopen("public.txt", "r");
    char *x = malloc(100 * sizeof(char));
    fscanf(f, "%s", x);
    printf("public read: %s\n", x);
    free(x);
    fclose(f);
}
void openPrivate() {
    FILE *f = fopen("private.txt", "r");
    char *x = malloc(100 * sizeof(char));
    fscanf(f, "%s", x);
    printf("private read: %s\n", x);
    free(x);
    fclose(f);
}
void exe() {
    char cmd[100] = "/bin/ls";
    char *argv[] = { "ls", NULL };
    char *environ[] = { NULL };
    execve(cmd, argv, environ);
}

void test_chdir() {
    int ret = chdir("aplusb");
    printf("chdir code: %d\n", ret);
}

void test_compile_c() {
    // 编译时应该不需要限制系统调用
    // 只需要限制资源使用即可
    test_chdir();
    char cmd[100] = "/usr/bin/g++";
    char *argv[] = { "g++", "a.cpp", "-o a-gen", "-std=c++11", NULL };
    char *environ[] = { NULL };
    execve(cmd, argv, environ);
}

void test_run_python2() {
    test_chdir();
    char cmd[100] = "/usr/bin/python2.7";
    char *argv[] = { "python", "a.py", NULL };
    char *environ[] = { NULL };
    execve(cmd, argv, environ);
}

void test_fork() {
    if (fork() == 0) {
        printf("son");
    } else {
        printf("fa");
    }
}
int main() {
    if (install_syscall_reporter()) {
        printf("install reporter failed");
        return 1;
    }
    export_scmp_filter();

    openPublic();
    openPrivate();
//    openPublic();
//    openPrivate();
    return 0;
}

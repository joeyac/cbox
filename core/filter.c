//
// Created by xjw on 10/21/18.
//

#include "filter.h"

int install_filter() {
    // TODO: add error handle
    scmp_filter_ctx ctx = NULL;
    ctx = seccomp_init(SCMP_ACT_TRAP);  // 不符合规则的调用发送信号
    if (!ctx) return -1;

    int system_calls[] = { SCMP_SYS(read), SCMP_SYS(write),
                           SCMP_SYS(open), SCMP_SYS(close),
                           SCMP_SYS(fstat), SCMP_SYS(mmap),
                           SCMP_SYS(munmap), SCMP_SYS(mprotect),
                           SCMP_SYS(brk),  SCMP_SYS(access),
                           SCMP_SYS(arch_prctl), SCMP_SYS(lseek),
                           SCMP_SYS(exit_group), SCMP_SYS(exit),
                           SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask),
                           SCMP_SYS(execve), SCMP_SYS(chdir), SCMP_SYS(clone), SCMP_SYS(wait4)};

    int syscalls_whitelist[] = {SCMP_SYS(read), SCMP_SYS(fstat),
                                SCMP_SYS(mmap), SCMP_SYS(mprotect),
                                SCMP_SYS(munmap), SCMP_SYS(uname),
                                SCMP_SYS(arch_prctl), SCMP_SYS(brk),
                                SCMP_SYS(access), SCMP_SYS(exit_group),
                                SCMP_SYS(close), SCMP_SYS(readlink),
                                SCMP_SYS(sysinfo), SCMP_SYS(write),
                                SCMP_SYS(writev), SCMP_SYS(lseek),
                                SCMP_SYS(open), SCMP_SYS(getdents),
                                SCMP_SYS(rt_sigaction),
                                SCMP_SYS(rt_sigprocmask),
                                SCMP_SYS(dup),
                                SCMP_SYS(dup2),
                                SCMP_SYS(openat), SCMP_SYS(execve)};
    int len = sizeof(syscalls_whitelist) / sizeof(int);
    for (int i = 0; i < len; i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls_whitelist[i], 0) != 0) {
            printf("i=%d failed\n", i);
            return -1;
        }
    }
//    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), STDERR_FILENO);
    seccomp_load(ctx);
    seccomp_release(ctx);
    return 0;

    // 文件读写打开关闭操作
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, STDIN_FILENO));

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    // 只允许向stderr或者stdout写入数据
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_LE, STDERR_FILENO));

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A0(SCMP_CMP_EQ, fileno(stdin)));
//    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t) "public.txt"));

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
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);

    // 以上为一个最基础的hello world程序所需系统调用

    // /bin/ls:
    // 对进程进行操作和设置
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);

    // python:
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    //

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);

    seccomp_load(ctx);

//    seccomp_export_bpf(ctx, STDOUT_FILENO);

    seccomp_release(ctx);
    return 0;
}
//
// Created by xjw on 11/4/18.
//

#include "rules.h"

const int allow_syscall_list[] = {
        // 文件读和关闭操作
        SCMP_SYS(read),
        SCMP_SYS(close),

        // 获取文件信息
        SCMP_SYS(fstat),

        // 将文件或设备映射或取消映射到内存中
        SCMP_SYS(mmap),
        SCMP_SYS(munmap),

        // 设置内存区域的保护
        SCMP_SYS(mprotect),

        // 更改数据段大小
        SCMP_SYS(brk),

        // 测试文件访问权限
        SCMP_SYS(access),

        // 设置特定于架构的线程状态
        SCMP_SYS(arch_prctl),

        // 重新定位read/write文件的偏移量
        SCMP_SYS(lseek),

        // 终止调用线程且终止调用进程线程组中的所有线程
        SCMP_SYS(exit_group),
        SCMP_SYS(exit),

        // 以上为一个最基础的hello world程序所需系统调用
};

scmp_filter_ctx apply_base_rules() {
    scmp_filter_ctx ctx = NULL;
    ctx = e_seccomp_init(SCMP_ACT_TRACE(getppid()));  // 默认向父进程发送信号

    int len = sizeof(allow_syscall_list) / sizeof(int);
    for (int i = 0; i < len; i++) {
        e_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow_syscall_list[i], 0);
    }
    // 只允许向stderr或者stdout写入数据
    e_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_LE, STDERR_FILENO));

//    e_seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    return ctx;
}

void add_c_rules(void) {
    scmp_filter_ctx ctx = apply_base_rules();

    e_seccomp_load(ctx);

    seccomp_release(ctx);
}

void add_python_rules(void) {

}
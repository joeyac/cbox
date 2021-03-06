//
// Created by xjw on 10/31/18.
//

#define __USE_GNU 1
#define _GNU_SOURCE 1

#include <stdio.h>
#include <unistd.h>
#include <seccomp.h>

#include <signal.h>
#include <sys/prctl.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <string.h>
#include <stddef.h>
#include <wait.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdlib.h>

#include "syscall-names.h"

#if defined(__i386__)
#define REG_RESULT	REG_EAX
#define REG_SYSCALL	REG_EAX
#define REG_ARG0	REG_EBX
#define REG_ARG1	REG_ECX
#define REG_ARG2	REG_EDX
#define REG_ARG3	REG_ESI
#define REG_ARG4	REG_EDI
#define REG_ARG5	REG_EBP
#elif defined(__x86_64__)
#define REG_RESULT	REG_RAX
#define REG_SYSCALL	REG_RAX
#define REG_ARG0	REG_RDI
#define REG_ARG1	REG_RSI
#define REG_ARG2	REG_RDX
#define REG_ARG3	REG_R10
#define REG_ARG4	REG_R8
#define REG_ARG5	REG_R9
#endif

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

const char * const msg = "system call invalid: ";

/* Since "sprintf" is technically not signal-safe, reimplement %d here. */
static void write_uint(char *buf, long long int val)
{
    int width = 0;
    long long int tens;

    if (val == 0) {
        strcpy(buf, "0");
        return;
    }
    for (tens = val; tens; tens /= 10)
        ++ width;
    buf[width] = '\0';
    for (tens = val; tens; tens /= 10)
        buf[--width] = (char) ('0' + (tens % 10));
}

static void helper(int nr, siginfo_t *info, void *void_context) {
    char buf[255];
    ucontext_t *ctx = (ucontext_t *)(void_context);
    unsigned int syscall;
    long long int arg0;
    if (info->si_code != SYS_SECCOMP)
        return;
    if (!ctx)
        return;

    syscall = (unsigned int) ctx->uc_mcontext.gregs[REG_SYSCALL];
    arg0 = ctx->uc_mcontext.gregs[REG_ARG0];
    strcpy(buf, msg);
    if (syscall < sizeof(syscall_names)) {
        strcat(buf, syscall_names[syscall]);
        strcat(buf, "(");
    }
    write_uint(buf + strlen(buf), syscall);
    if (syscall < sizeof(syscall_names))
        strcat(buf, ")");
    strcat(buf, ": arg1=");
    write_uint(buf + strlen(buf), arg0);
    strcat(buf, "\n");
    write(STDOUT_FILENO, buf, strlen(buf));
    _exit(1);
}

static int install_helper() {
    struct sigaction act;
    sigset_t mask;
    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);

    act.sa_sigaction = &helper;
    act.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &act, NULL) < 0) {
        perror("sigaction");
        return -1;
    }
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
        perror("sigprocmask");
        return -1;
    }
    return 0;
}


void print_exit(int status)
{
    if (WIFEXITED(status))
        printf("normal termination, exit status = %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("abnormal termination, signal number = %d%s\n", WTERMSIG(status),
#ifdef WCOREDUMP
               WCOREDUMP(status) ? (" core file generated") : (""));
#else
        "");
#endif
    else if (WIFSTOPPED(status))
        printf("child stopped, signal number=%d\n", WSTOPSIG(status));
}

void child() {
    printf("child before ptrace PTRACE_TRACEME\n");
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    printf("child after ptrace PTRACE_TRACEME\n");

    // 不允许子进程获得新权限
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    scmp_filter_ctx ctx = NULL;

    // 默认允许所有系统调用
    ctx = seccomp_init(SCMP_ACT_ALLOW);

    // 只允许输出到stdout
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
    seccomp_rule_add(ctx, SCMP_ACT_TRACE(getppid()), SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_NE, STDOUT_FILENO));

//        seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(write), 0);
    // 应用过滤器
    seccomp_load(ctx);

    // 释放内存
    seccomp_release(ctx);

    // 用a.cpp替换子进程
    char cmd[100] = "/home/xjw/Desktop/crazyX/team/LETTersOnline/crazybox/cbox/tests/a5.o";
    char *argv[] = { NULL };
    char *environ[] = { NULL };

//    sleep(2);
//    printf("child before ptrace stop\n");
    kill(getpid(), SIGSTOP);
//    printf("child after ptrace stop\n");
    execve(cmd, argv, environ);
    puts("ERROR:");
    puts(strerror(errno));
    _exit(1);
}

pid_t child_pid;
void killer(int sig) {
    // 终止子进程，用于超出wall time等异常情况
    struct sigaction sigact;

    /* Reset signal handlers to default */
    sigact.sa_handler = SIG_DFL;
    sigact.sa_flags = 0;
    if (sigemptyset(&sigact.sa_mask) != 0) {
        puts("could not initialize signal mask");
    }
    if (sigaction(SIGTERM,&sigact,NULL) != 0) {
        puts("could not restore signal handler");
    }
    if (sigaction(SIGALRM,&sigact,NULL) != 0) {
        puts("could not restore signal handler");
    }
    if (sig == SIGALRM) {
        puts("wall time limit exceeded");
    } else {
        puts("received signal %d: aborting command");
    }
    /* First try to kill graciously, then hard.
    Don't report an already exited process as error. */
    printf("%d %d\n", getpid(), child_pid);
    if (kill(-child_pid, SIGTERM) < 0) {
        fprintf(stderr, "kill child1: %s\n", strerror(errno));
    }
    sleep(1);
    if (kill(-child_pid, SIGKILL) < 0) {
        fprintf(stderr, "kill child2: %s\n", strerror(errno));
    }
}


static int wait_for_syscall(pid_t child)
{
    int status;
    struct sigaction sigact;
    sigset_t mask;
    sigemptyset(&mask);

    if ( sigaddset(&mask,SIGALRM)!=0 ||
         sigaddset(&mask,SIGTERM)!=0 ) puts("setting signal mask");
    sigact.sa_handler = killer;
    sigact.sa_flags   = SA_RESETHAND | SA_RESTART;
    sigact.sa_mask    = mask;
    if ( sigaction(SIGTERM,&sigact,NULL)!=0 ) {
        puts("installing signal handler");
    }
    if ( sigaction(SIGALRM,&sigact,NULL)!=0 ) {
        puts("installing signal handler");
    }
    struct itimerval itimer;
    itimer.it_interval.tv_sec  = 0;
    itimer.it_interval.tv_usec = 0;
    itimer.it_value.tv_sec  = 2;
    itimer.it_value.tv_usec = 0;
    if ( setitimer(ITIMER_REAL,&itimer,NULL)!=0 ) {
        puts("setting timer");
    }

    while (1) {
        puts("=========start=======");
        printf("before ptrace continue\n");
        ptrace(PTRACE_CONT, child, 0, 0);
        printf("after ptrace continue\n");

        int ret = waitpid(child, &status, 0);
        printf("[waitpid status: 0x%08x]\n", status);
        printf("pid:%d, ret:%d, status=%d, %s\n", getpid(), ret, status, strerror(errno));
        print_exit(status);
        puts("=========end=======");
        // 判断是否是seccomp限制的规则，这个判断条件可以在ptrace文档中找到
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            long syscall;
            syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, 0);
//            long arg0;
//            arg0 = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RDI, 0);
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            printf("system call invalid: %s(%ld) with args: 0x%llx 0x%llx 0x%llx\n",
                   syscall < sizeof(syscall_names) ? syscall_names[syscall] : "null",
                   syscall,
                   regs.rdi, regs.rsi, regs.rdx);
            kill(child, SIGKILL);
            return 0;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status) ) {
            puts("exited");
            return 1;
        }



    }
}


int main() {
    pid_t pid = fork();
    if (pid < 0) _exit(1);
    else if (pid == 0) {
        child();
    } else {
        int status;
        waitpid(pid, &status, 0);
//        printf("[waitpid status: 0x%08x]\n", status);
//        printf("pid:%d, ret:%d, status=%d, %s\n", getpid(), ret, status, strerror(errno));
//        print_exit(status);
//        puts("========");
        child_pid = pid;
        printf("%s\n", strerror(errno));
        setpgid(pid,pid);
        printf("child=%d\n", child_pid);
        printf("%s\n", strerror(errno));
        long ret = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
        printf("ret=%ld,%s\n", ret, strerror(errno));
        errno = 0;
        while (1) {
            if (wait_for_syscall(pid) != 0) break;
        }
    }
    return 0;
}
//
// Created by xjw on 11/5/18.
//

#ifndef CBOX_BOX_H
#define CBOX_BOX_H

#include "syscall.h"

#include "wcommon.h"

#include "rules.h"

#include "wrap_tracee.h"
#include "wrap_tracer.h"

#include <math.h>

#include <sys/times.h>
#include <sys/user.h>
#include <sys/reg.h>


// limit for child process
typedef struct {
    // setrlimit
    double cpu_time;      // s

    long data;          // kb
    long address_space; // kb
    long stack;         // kb

    long output_size;   // kb
    int nproc;          //

    double wall_time; // 如果<=0,默认为cpu_time

    int time_flag;  // 0 for enable cpu_time and wall_time
                    // 1 for enable only wall_time
                    // 2 for enable only cpu_time (danger)

    // execv
    char *dir;      // chdir (& chroot?
    char *file;     // executable file
    char **argv;
    char **envp;

    // file descriptor
    int _stdin;
    int _stdout;
    int _stderr;

    // set gid uid
    // #TODO: if need? or just set to 65534(nobody)?
    uid_t uid;
    gid_t gid;

    // seccomp rule
    int seccomp;    // 0: no set - compile program
                    // 1: c/c++ program
                    // 2-

    int debug;      // 如果debug=1，将会输出所有的非法系统调用情况而不会终止目标程序
    int verbose;    // 如果verbose=0，会忽略所有警告信息
    FILE* meta_file;// 日志输出，如果为null，将会向stderr输出
} Config;


enum __cbox_result {
    CBOX_INTERNAL_ERROR = -1,

    CBOX_SUCCESS = 0,
    CBOX_INVALID_CALL = 1,
    CBOX_RUNTIME_ERROR = 2,
    CBOX_NPROC_LIMIT_EXCEED = 3,
    CBOX_OUTPUT_LIMIT_EXCEED = 4,
    CBOX_MEMORY_LIMIT_EXCEED = 5,
    CBOX_CPUTIME_LIMIT_EXCEED = 6,
    CBOX_WALLTIME_LIMIT_EXCEED = 7,
};

// cbox result, if internal error occurred, result may be empty
typedef struct {
    long cpu_time;      // result in ms
    long wall_time;     // result in ms
    long memory;        // result in kb
    int signal;
    int exit_code;
    enum __cbox_result result;
} Result;

static const Result EmptyResult;

const char * const msg = "system call invalid: ";

void print_exit(int status) {
    if (WIFEXITED(status))
        fprintf(stderr, "normal termination, exit status = %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(stderr, "abnormal termination, signal number = %d%s\n", WTERMSIG(status),
#ifdef WCOREDUMP
                WCOREDUMP(status) ? (" core file generated") : (""));
#else
        "");
#endif
    else if (WIFSTOPPED(status))
        fprintf(stderr, "child stopped, signal number=%d\n", WSTOPSIG(status));
}


void tracee(Config *config) {
    // 创建一个新的回话并令当前子进程为组长
    // 方便通过kill(-pid, SIG)的方式统一发送信号
    e_setsid();

    // 不允许子进程组获得新权限
    e_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // 设置为tracee
    e_ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    // #TODO: setrlimit

    if (config->dir && *config->dir) e_chdir(config->dir);

    if (config->_stdin >= 0) e_dup2(config->_stdin, STDIN_FILENO);

    if (config->_stdout >= 0) e_dup2(config->_stdout, STDOUT_FILENO);

    if (config->_stderr >= 0) e_dup2(config->_stderr, STDERR_FILENO);

    if (config->seccomp) {
        switch (config->seccomp) {
            case 1: add_c_rules();
            default: e_app_error("no such seccomp rule support");
        }
    }


    e_kill(getpid(), SIGSTOP);

    e_execve(config->file, config->argv, config->envp);
}

int wait_for_ptrace(pid_t child) {
    // 正常情况下由于一开始暂停一次，如果没有非法系统调用，那么以下循环会执行两次（一次开始的暂停，一次程序结束）
    // 如果有非法系统调用，应该执行三次

    int status;
    while (1) {
        ptrace(PTRACE_CONT, child, 0, 0);
        int ret = waitpid(child, &status, 0);

        fprintf(LOGFILE,"[waitpid status: 0x%08x]\n", status);
        fprintf(LOGFILE, "pid:%d, ret:%d, status=%d, %s\n", getpid(), ret, status, strerror(errno));
        print_exit(status);
        if (WIFEXITED(status) || WIFSIGNALED(status) ) {
            fprintf(LOGFILE, "child exit.\n");
            return 1;
        }
        // 判断是否是seccomp限制的规则，这个判断条件可以在ptrace文档中找到
        if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            long syscall;
            syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, 0);
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            fprintf(LOGFILE, "system call invalid: %s(%ld) with args: 0x%llx 0x%llx 0x%llx\n",
                   syscall < sizeof(syscall_names) ? syscall_names[syscall] : "null",
                   syscall, regs.rdi, regs.rsi, regs.rdx);
            return 0;
        }
    }
}


int tracer_debug(Result *result) {
    *result = EmptyResult;
    int status;
    waitpid(child_pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESECCOMP);
    while (1) {
        if (wait_for_ptrace(child_pid)) break;
    }
    return 0;
}




void collect_exit_info(Result *result, struct rusage *usage,
        struct timeval *start_time, struct timeval *end_time,
                struct tms *start_tms, struct tms *end_tms) {

}


int tracer(Result *result, double wall_time) {
    int rc = 0, status;
    *result = EmptyResult;

    if (r_waitpid(child_pid, &status, 0) < 0)
        return r_app_error("first wait pid failed");

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return r_app_error("here child should be stopped with SIGSTOP signal");

    if (r_ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESECCOMP) < 0)
        return r_app_error("ptrace(PTRACE_SETOPTIONS) error");

    if (r_ptrace(PTRACE_CONT, child_pid, 0, 0) < 0)
        return r_app_error("ptrace(PTRACE_CONT-1) error");

    if (r_waitpid(child_pid, &status, 0) < 0)
        return r_app_error("second wait pid failed");

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        return r_app_error("here child should be stopped with SIGTRAP signal");

    // wall time超时处理, 增加SIGTERM和SIGALRM信号处理
    if ((rc = r_add_wall_time_sigaction()) < 0)
        return rc;

    struct timeval start_time, end_time;
    struct itimerval itimer;
    double integer;
    struct tms start_tms, end_tms;
    struct rusage usage;

    itimer.it_interval.tv_sec  = 0;
    itimer.it_interval.tv_usec = 0;
    itimer.it_value.tv_sec  = (long) wall_time;
    itimer.it_value.tv_usec = (long)(modf(wall_time, &integer) * 1E6);

    // 发送这个信号之后execve才正式开始执行
    if (r_ptrace(PTRACE_CONT, child_pid, 0, 0) < 0)
        return r_app_error("ptrace(PTRACE_CONT-2) error");

    // 开始统计时间
    // wall-time
    if (gettimeofday(&start_time, NULL) < 0)
        return r_app_error("get start time of day failed");

    if (setitimer(ITIMER_REAL, &itimer, NULL) < 0)
        return r_app_error("setitimer failed");

    // sys-time & user-time
    if (times(&start_tms) == (clock_t) -1)
        return r_app_error("get start tms failed");

    // 这次wait子进程肯定会退出，手机信息
    if (wait4(child_pid, &status, WUNTRACED, &usage) == (pid_t) -1)
        return r_app_error("third wait pid failed");

    if (times(&end_tms) == (clock_t) -1)
        return r_app_error("get end tms failed");

    if (gettimeofday(&end_time, NULL) < 0)
        return r_app_error("get end time of day failed");

    if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
        long syscall;
        syscall = ptrace(PTRACE_PEEKUSER, child_pid, sizeof(long)*ORIG_RAX, 0);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        fprintf(LOGFILE, "system call invalid: %s(%ld) with args: 0x%llx 0x%llx 0x%llx\n",
                syscall < sizeof(syscall_names) ? syscall_names[syscall] : "null",
                syscall, regs.rdi, regs.rsi, regs.rdx);
    }

    collect_exit_info(result, &usage, &start_time, &end_time, &start_tms, &end_tms);
    return rc;
}


int CboxRun(Config *config, Result *result) {
    // 返回-1时说明发生了内部错误，result将为空，需要查看LOGFILE输出的信息
    LOGFILE = config->meta_file == NULL ? stderr : config->meta_file;
    VERBOSE = config->verbose;
    child_pid = -1;
    received_signal = -1;

    // TODO: think how to set wall time limit and cpu time limit efficient
    double wall_time = config->wall_time > 0 ? config->wall_time : config->cpu_time * 3.0;

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(LOGFILE, "fork failed\n");
        return -1;
    }
    else if (pid == 0) {
        tracee(config);
        // 这里不会返回，因为tracee中正常执行将被execve替换掉
        // 否则也会exit(exit_failure);退出
        return -1;
    }
    else {
        child_pid = pid;

        if (config->debug)
            return tracer_debug(result);
        else
            return tracer(result, wall_time);
    }
}

#endif //CBOX_BOX_H

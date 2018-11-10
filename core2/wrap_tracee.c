//
// Created by xjw on 11/10/18.
//

#include "wrap_tracee.h"

void e_unix_error(char *msg) {
    fprintf(LOGFILE, "%s: %s\n", msg, strerror(errno));
    exit(exit_failure);
}

void e_app_error(const char *msg) {
    fprintf(LOGFILE, "error: %s\n", msg);
    exit(exit_failure);
}

void e_chdir(const char *path) {
    if (chdir(path) < 0)
        e_unix_error("chdir failed");
}

void e_execve(const char *filename, char *const *argv, char *const *envp) {
    if (execve(filename, argv, envp) < 0)
        e_unix_error("execve failed");
}

void e_kill(pid_t pid, int signum) {
    if (kill(pid, signum) < 0)
        e_unix_error("kill failed");
}

void e_dup2(int fd1, int fd2) {
    if (dup2(fd1, fd2) < 0)
        e_unix_error("dup2 failed");
}

void e_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
    if (ptrace(request, pid, addr, data) == -1)
        e_unix_error("ptrace failed");
}

void e_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    if (prctl(option, arg2, arg3, arg4, arg5) == -1)
        e_unix_error("prctl failed");
}

void e_setrlimit(int resource, rlim_t cur, rlim_t max) {
    struct rlimit limit;
    limit.rlim_cur = cur;
    limit.rlim_max = max;
    if (setrlimit(resource, &limit) == -1)
        e_unix_error("setrlimit failed");
}

scmp_filter_ctx e_seccomp_init(uint32_t def_action) {
    scmp_filter_ctx ctx = seccomp_init(def_action);
    if (!ctx) e_app_error("init seccomp failed");
    return ctx;
}

void e_seccomp_rule_add(scmp_filter_ctx ctx, uint32_t action, int syscall, unsigned int arg_cnt, ...) {
    va_list args;
    va_start(args, arg_cnt);
    int ret = seccomp_rule_add(ctx, action, syscall, arg_cnt, args);
    va_end(args);
    if (ret < 0)
        e_app_error("add seccomp rule failed");
}

void e_seccomp_load(scmp_filter_ctx ctx) {
    if (seccomp_load(ctx) < 0)
        e_app_error("load seccomp rule failed");
}

void e_setsid(void) {
    if (setsid() == -1)
        e_unix_error("setsid failed");
}
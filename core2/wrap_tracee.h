//
// Created by xjw on 11/10/18.
// Wrap function used by tracee process to simplify code logic.
// The function mainly used before `execve` system call.
// if execute function failed, exit with code -1 and log message.
// function name start with `e_`.

#ifndef CBOX_WRAPPERS_TRACEE_H
#define CBOX_WRAPPERS_TRACEE_H

#include "wcommon.h"

void e_unix_error(char *msg);

void e_app_error(const char *msg);

void e_execve(const char *filename, char *const *argv, char *const *envp);

void e_kill(pid_t pid, int signum);

void e_dup2(int fd1, int fd2);

void e_ptrace(enum __ptrace_request request, pid_t pid,
              void *addr, void *data);

void e_prctl(int option, unsigned long arg2, unsigned long arg3,
            unsigned long arg4, unsigned long arg5);

void e_chdir(const char *path);

void e_setrlimit(int resource, rlim_t cur, rlim_t max);

scmp_filter_ctx e_seccomp_init(uint32_t def_action);

void e_seccomp_rule_add(scmp_filter_ctx ctx, uint32_t action, int syscall, unsigned int arg_cnt, ...);

void e_seccomp_load(scmp_filter_ctx ctx);

void e_setsid(void);

#endif //CBOX_WRAPPERS_TRACEE_H

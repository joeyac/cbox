//
// Created by xjw on 11/10/18.
// Wrap function used by tracer process to simplify code logic.
// if execute function failed, stop child group if exist, then return with code -1 and log message.
// function name start with `r_`.

#ifndef CBOX_WRAPPERS_TRACER_H
#define CBOX_WRAPPERS_TRACER_H

#include "wcommon.h"



void error_terminate() {
//    fprintf(LOGFILE, "error: %s: %s\n", reason, strerror(errno));
    if (child_pid > 0) {
        if (kill(-child_pid, SIGTERM) != 0 && errno != ESRCH)
            app_warning("unable to send SIGTERM to children group while terminating "
                        "due to previous error: %s\n", strerror(errno));
        delay_for_kill();

        if (kill(-child_pid, SIGKILL) != 0 && errno != ESRCH)
            app_warning("unable to send SIGKILL to children group while terminating "
                        "due to previous error: %s\n", strerror(errno));
        delay_for_kill();

        // 避免重复调用
        child_pid = -1;
    }
}

int r_unix_error(char *msg) {
    fprintf(LOGFILE, "%s: %s\n", msg, strerror(errno));
    error_terminate();
    return exit_failure;
}

int r_app_error(const char *msg) {
    fprintf(LOGFILE, "error: %s\n", msg);
    error_terminate();
    return exit_failure;
}

int r_kill(pid_t pid, int signum) {
    // ESRCH = no such process
    if (kill(pid, signum) < 0 && errno != ESRCH)
        return r_unix_error("kill failed");
    return 0;
}

int r_ptrace(enum __ptrace_request request, pid_t pid, void *addr, enum __ptrace_setoptions data) {
    if (ptrace(request, pid, addr, data) == -1)
        return r_unix_error("ptrace failed");
    return 0;
}

int r_waitpid(pid_t pid, int *iptr, int options) {
    if (waitpid(pid, iptr, options) < 0)
        return r_unix_error("waitpid failed");
    return 0;
}


void killer(int sig) {
    // 终止子进程，用于超出wall time等异常情况
    struct sigaction sigact;

    // 重置为默认信号处理
    sigact.sa_handler = SIG_DFL;
    sigact.sa_flags = 0;
    if (sigemptyset(&sigact.sa_mask) != 0) {
        app_warning("could not initialize signal mask");
    }
    if (sigaction(SIGTERM,&sigact,NULL) != 0) {
        app_warning("could not restore signal handler");
    }
    if (sigaction(SIGALRM,&sigact,NULL) != 0) {
        app_warning("could not restore signal handler");
    }
    if (sig == SIGALRM) {
        app_warning("wall time limit exceeded");
    } else {
        app_warning("received signal %d: aborting command", sig);
    }
    received_signal = sig;

    // 先发送正常的TERM信号终止程序
    r_kill(-child_pid, SIGTERM);
    delay_for_kill();

    // 再发送强制停止信号
    r_kill(-child_pid, SIGKILL);
    delay_for_kill();
}


int r_add_wall_time_sigaction() {
    struct sigaction sigact;
    sigset_t mask;
    sigemptyset(&mask);
    if (sigaddset(&mask, SIGALRM) != 0 || sigaddset(&mask, SIGTERM) != 0)
        return r_app_error("sig add set error");

    sigact.sa_handler = killer;
    sigact.sa_flags   = SA_RESETHAND | SA_RESTART;
    sigact.sa_mask    = mask;
    if (sigaction(SIGTERM, &sigact, NULL) != 0)
        return r_app_error("sigaction with SIGTERM error");

    if (sigaction(SIGALRM, &sigact, NULL) != 0)
        return r_app_error("sigaction with SIGALRM error");
    return 0;
}

#endif //CBOX_WRAPPERS_TRACER_H

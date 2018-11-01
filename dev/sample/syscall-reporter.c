//
// Created by xjw on 10/28/18.
//

/*
 * syscall reporting example for seccomp
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Will Drewry <wad@chromium.org>
 *  Kees Cook <keescook@chromium.org>
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "syscall-reporter.h"
#include "syscall-names.h"

const char * const msg_needed = "Looks like you also need syscall: ";

/* Since "sprintf" is technically not signal-safe, reimplement %d here. */
static void write_uint(char *buf, unsigned int val)
{
    int width = 0;
    unsigned int tens;

    if (val == 0) {
        strcpy(buf, "0");
        return;
    }
    for (tens = val; tens; tens /= 10)
        ++ width;
    buf[width] = '\0';
    for (tens = val; tens; tens /= 10)
        buf[--width] = '0' + (tens % 10);
}

static void reporter(int nr, siginfo_t *info, void *void_context)
{
    char buf[128], *arg0, *arg1;
    ucontext_t *ctx = (ucontext_t *)(void_context);
    unsigned int syscall;
    if (info->si_code != SYS_SECCOMP)
        return;
    if (!ctx)
        return;
    write_uint(buf + strlen(buf), REG_SYSCALL);
    strcat(buf, "\n");
    write_uint(buf + strlen(buf), REG_ARG0);
    strcat(buf, "\n");
    write_uint(buf + strlen(buf), REG_ARG1);
    strcat(buf, "\n");
    syscall = ctx->uc_mcontext.gregs[REG_SYSCALL];
    arg0 = (char *) ctx->uc_mcontext.gregs[REG_ARG0];
//    arg1 = (char *) ctx->uc_mcontext.gregs[REG_ARG1];
    strcat(buf, msg_needed);
    if (syscall < sizeof(syscall_names)) {
        strcat(buf, syscall_names[syscall]);
        strcat(buf, "(");
    }
    write_uint(buf + strlen(buf), syscall);
    if (syscall < sizeof(syscall_names))
        strcat(buf, ")");
    strcat(buf, "\n");
    strcat(buf, arg0);
//    strcat(buf, arg1);
    write(STDOUT_FILENO, buf, strlen(buf));
    _exit(1);
}

int install_syscall_reporter(void)
{
    struct sigaction act;
    sigset_t mask;
    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);
    sigaddset(&mask, SIGSYS);

    act.sa_sigaction = &reporter;
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
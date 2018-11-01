//
// Created by xjw on 10/28/18.
//

#ifndef CBOX_SYSCALL_REPORTER_H
#define CBOX_SYSCALL_REPORTER_H

/*
 * syscall reporting example for seccomp
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Kees Cook <keescook@chromium.org>
 *  Will Drewry <wad@chromium.org>
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef _BPF_REPORTER_H_
#define _BPF_REPORTER_H_

#include "seccomp-bpf.h"
/* Since this redfines "KILL_PROCESS" into a TRAP for the reporter hook,
 * we want to make sure it stands out in the build as it should not be
 * used in the final program.
 */
#warning "You've included the syscall reporter. Do not use in production!"
#undef KILL_PROCESS
#define KILL_PROCESS \
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)

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

extern int install_syscall_reporter(void);

#endif

#endif //CBOX_SYSCALL_REPORTER_H

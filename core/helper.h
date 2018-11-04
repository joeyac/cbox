//
// Created by xjw on 11/1/18.
//

#ifndef CBOX_HELPER_H
#define CBOX_HELPER_H

#ifndef __USE_GNU
#define __USE_GNU 1

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

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

static void write_uint(char *buf, long long int val);
static void helper(int nr, siginfo_t *info, void *void_context);
int install_helper();
#endif

#endif //CBOX_HELPER_H

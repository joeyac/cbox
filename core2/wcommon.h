//
// Created by xjw on 11/4/18.
// wrapper function: if error occurred, put friendly msg on stderr and exit or return -1.

#ifndef CBOX_WRAPPERS_H
#define CBOX_WRAPPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <zconf.h>
#include <stdbool.h>

#include <wait.h>
#include <time.h>
#include <seccomp.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>

const int exit_failure = -1;
const struct timespec kill_delay = { 0, 100000000L }; /* 0.1 seconds */

extern int VERBOSE;
extern FILE* LOGFILE;
extern pid_t child_pid;
extern volatile sig_atomic_t received_signal;


/* error-handling functions */
void unix_error(char *msg);

void posix_error(int code, char *msg);

void app_error(char *msg);

void app_error_code(int code, char *msg);

void app_warning(const char *, ...) __attribute__((format (printf, 1, 2)));
/* error-handling functions end */

int Close(int fd);

pid_t Wait(int *status);

pid_t Waitpid(pid_t pid, int *iptr, int options);

unsigned int Sleep(unsigned int secs);

unsigned int Alarm(unsigned int seconds);

void Gettimeofday(struct timeval *__restrict __tv,
                 __timezone_ptr_t __tz) {
    if (gettimeofday(__tv, __tz))
        unix_error("get time of day error");
}

/* wrapper lib functions end */

/* cbox functions */
void delay_for_kill() {
    /* Prefer nanosleep over sleep because of higher resolution and
   it does not interfere with signals. */
    nanosleep(&kill_delay,NULL);
}

/* cbox functions end */

#endif //CBOX_WRAPPERS_H

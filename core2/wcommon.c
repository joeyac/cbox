//
// Created by xjw on 11/4/18.
// wrapper function: if error occurred, put friendly msg on LOGFILE and exit or return -1.
//


#include "wcommon.h"

int VERBOSE = 0;
FILE* LOGFILE = NULL;
pid_t child_pid = -1;
volatile sig_atomic_t received_signal = -1;

/**************************
 * Error-handling functions
 **************************/
/* $begin errorfuns */
/* $begin unixerror */
void unix_error(char *msg) /* Unix-style error */
{
    fprintf(LOGFILE, "%s: %s\n", msg, strerror(errno));
    exit(exit_failure);
}

/* $end unixerror */

void posix_error(int code, char *msg) /* Posix-style error */
{
    fprintf(LOGFILE, "%s: %s\n", msg, strerror(code));
    exit(exit_failure);
}

void app_error_code(int code, char *msg) /* Application error */
{
    fprintf(LOGFILE, "%s\n", msg);
    exit(code);
}

void app_error(char *msg) /* Application error */
{
    app_error_code(exit_failure, msg);
}

void app_warning(const char *format, ...)
{
    if (!VERBOSE) return;
    va_list ap;
    va_start(ap,format);
    fprintf(LOGFILE,"warning: ");
    vfprintf(LOGFILE, format, ap);
    fprintf(LOGFILE, "\n");
    va_end(ap);
}

int Close(int fd) {
    int re;
    do {
        re = close(fd);
    } while ((re == -1) && (errno == EINTR));
    if (re < 0)
        unix_error("cbox close fd error");
    return re;
}

pid_t Wait(int *status) {
    pid_t pid;

    if ((pid = wait(status)) < 0)
        unix_error("Wait error");
    return pid;
}

pid_t Waitpid(pid_t pid, int *iptr, int options) {
    pid_t retpid;

    if ((retpid = waitpid(pid, iptr, options)) < 0)
        unix_error("Waitpid error");
    return (retpid);
}

unsigned int Sleep(unsigned int secs) {
    unsigned int rc;

    if ((rc = sleep(secs)) < 0)
        unix_error("Sleep error");
    return rc;
}

unsigned int Alarm(unsigned int seconds) {
    return alarm(seconds);
}


//
// Created by xjw on 10/21/18.
//
#include "utils.h"

// wrapper of useful function
// send user signal if failed

/**************************
 * Error-handling functions
 **************************/
/* $begin errorfuns */
/* $begin unixerror */
void unix_error(char *msg) /* Unix-style error */
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(0);
}

/* $end unixerror */

void posix_error(int code, char *msg) /* Posix-style error */
{
    fprintf(stderr, "%s: %s\n", msg, strerror(code));
    exit(0);
}

void dns_error(char *msg) /* DNS-style error */
{
    fprintf(stderr, "%s: DNS error %d\n", msg, h_errno);
    exit(0);
}

void app_error(char *msg) /* Application error */
{
    fprintf(stderr, "%s\n", msg);
    exit(0);
}
/* $end errorfuns */


// SIGUSR1 signal for internal sandbox error
void Setrlimit(__rlimit_resource_t resource, const struct rlimit *rlimits) {
    if (setrlimit(resource, rlimits) != 0) {
        raise(SIGUSR1);
        app_error("set rlimit failed");
    }
}


void Execve(const char *filename, char *const *argv, char *const *envp) {
    if (execve(filename, argv, envp) < 0)
        unix_error("Execve error");
}

void Close(int fd) {
    int rc;
    if ((rc = close(fd)) < 0)
        unix_error("Close error");
}

int Dup2(int fd1, int fd2) {
    int rc;
    if ((rc = dup2(fd1, fd2)) < 0)
        unix_error("Dup2 error");
    return rc;
}

void Fclose(FILE *fp) {
    if (fclose(fp) != 0)
        unix_error("Fclose error");
}

FILE *Fopen(const char *filename, const char *mode) {
    FILE *fp;
    if ((fp = fopen(filename, mode)) == NULL)
        unix_error("Fopen error");
    return fp;
}

int Chdir(const char *path) {
    int rc;
    if ((rc = chdir(path)) < 0)
        unix_error("Chdir failed");
    return rc;
}
/* built-in functions end */


/* cbox functions and defines */
void cbox_set_rlimit(int resource, rlim_t cur, rlim_t max) {
    struct rlimit limit;
    limit.rlim_cur = cur;
    limit.rlim_max = max;
    Setrlimit(resource, &limit);
}

int cbox_close_fd(int fd) {
    int re;
    do {
        re = close(fd);
    } while ((re == -1) && (errno == EINTR));
    if (re < 0)
        unix_error("cbox close fd error");
    return re;
}

/* cbox functions and defines end */
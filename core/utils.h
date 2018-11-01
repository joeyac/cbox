//
// Created by xjw on 10/21/18.
//

#ifndef CBOX_UTILS_H
#define CBOX_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <sys/resource.h>
#include <stdio.h>
#include <netdb.h>


/* error-handling functions */
void unix_error(char *msg);

void posix_error(int code, char *msg);

void dns_error(char *msg);

void app_error(char *msg);
/* error-handling functions end */


/* built-in functions */
void Setrlimit(__rlimit_resource_t resource, const struct rlimit * rlimits);

void Execve(const char *filename, char *const argv[], char *const envp[]);

void Close(int fd);

int Dup2(int fd1, int fd2);

void Fclose(FILE *fp);

FILE *Fopen(const char *filename, const char *mode);

int Chdir(const char *path);
/* built-in functions end */

/* cbox functions and defines */
typedef struct child_config {
    unsigned long cpu_time;
    unsigned long memory;
    unsigned long address_space;
    char *dir;
    char *file;
    char **argv;
    char **envp;
    int nproc;
    int _stdin;
    int _stdout;
    int _stderr;
} config;

void cbox_set_rlimit(int resource, rlim_t cur, rlim_t max);

int cbox_close_fd(int fd);

/* cbox functions end */
#endif //CBOX_UTILS_H

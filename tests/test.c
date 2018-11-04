//
// Created by xjw on 11/1/18.
//
#include "test.h"


void test_ls() {
    char cmd[100] = "/bin/ls";
    char *argv[] = { "ls", NULL };
    char *environ[] = { NULL };
    execve(cmd, argv, environ);
}

void test_chdir() {
    chdir("aplusb");
}

void test_compile_c() {
    // 编译时应该不需要限制系统调用
    // 只需要限制资源使用即可
    test_chdir();
    char cmd[100] = "/usr/bin/g++";
    char *argv[] = { "g++", "a.cpp", "-o a-gen", "-std=c++11", NULL };
    char *environ[] = { NULL };
    execve(cmd, argv, environ);
}

void test_run_python2() {
    test_chdir();
    char cmd[100] = "/usr/bin/python2.7";
    char *argv[] = { "python", "a.py", NULL };
    char *environ[] = { NULL };
    execve(cmd, argv, environ);
}

void test_fork() {
    if (fork() == 0) {
        printf("son");
    } else {
        printf("fa");
    }
}

void test_run_c() {
    char cmd[100] = "./a";
    char *argv[] = { "a", NULL };
    char *environ[] = { NULL };
    execvp(cmd, argv);
}
void catchSigSon(int sig) {
    printf("get sig: %d\n", sig);
}

extern char *msg;
static void write_uint(char *buf, long long int val)
{
    int width = 0;
    long long int tens;

    if (val == 0) {
        strcpy(buf, "0");
        return;
    }
    for (tens = val; tens; tens /= 10)
        ++ width;
    buf[width] = '\0';
    for (tens = val; tens; tens /= 10)
        buf[--width] = (char) ('0' + (tens % 10));
}

static void sonHelper(int nr, siginfo_t *info, void *void_context) {
    printf("nr=%d\n", nr);
    char buf[255];
    ucontext_t *ctx = (ucontext_t *)(void_context);
    unsigned int syscall;
//    if (info->si_code != SYS_SECCOMP)
//        return;
    if (!ctx)
        return;

    syscall = (unsigned int) ctx->uc_mcontext.gregs[REG_SYSCALL];
    strcpy(buf, msg);
    if (syscall < sizeof(syscall_names)) {
        strcat(buf, syscall_names[syscall]);
        strcat(buf, "(");
    }
    write_uint(buf + strlen(buf), syscall);
    if (syscall < sizeof(syscall_names))
        strcat(buf, ")");
    strcat(buf, "\n");
    write(STDOUT_FILENO, buf, strlen(buf));
//    _exit(1);

    int status;
    struct rusage resource_usage;
    if (wait3(&status, WUNTRACED, &resource_usage) == -1) {
        printf("error child\n");
        _exit(1);
    }
    printf("status: %d\n", WIFSIGNALED(status));

    printf("SIGUSR1: %d\n", SIGUSR1);
    printf("SIGSEGV: %d\n", SIGSEGV);

    printf("WTERMSIG: %d\n", WTERMSIG(status));
    printf("status code: %d\n", WEXITSTATUS(status));
    _exit(0);
}

int installSonSig() {
    struct sigaction act;
    sigset_t mask;
    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    act.sa_sigaction = &sonHelper;
    act.sa_flags = SA_SIGINFO;
    if (sigaction(SIGCHLD, &act, NULL) < 0) {
        perror("sigaction");
        return -1;
    }
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
        perror("sigprocmask");
        return -1;
    }
}

int main() {
    pid_t child_pid = fork();
    signal(SIGCHLD, catchSigSon);
    if (installSonSig()) {
        printf("install installSonSig failed");
        return 1;
    }

    if (child_pid < 0)
        return 1;
    if (child_pid == 0) {
        FILE* file = fopen("data.out", "w");
        dup2(fileno(file), STDOUT_FILENO);
        if (install_helper()) {
            printf("install helper failed");
            return 1;
        }
        if (install_filter()) {
            printf("install filter failed");
            return 1;
        }
        test_run_c();
        printf("error\n");
    } else {
        while(1);
    }

    return 0;
}
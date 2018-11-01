#include <zconf.h>
#include "main.h"

int func(int x, int y, const char *s, c_result *result) {
    result->val1 = x;
    result->val2 = y;
    result->str = malloc(strlen(s) + 1);
    stpcpy(result->str, s);
    pid_t fpid = fork();
    if (fpid < 0)
        printf("error in fork!");
    else if (fpid == 0) {
        dup2(x, fileno(stdin));
        dup2(y, fileno(stdout));
        scanf("%ld", &result->val2);
        printf("%ld", result->val2);
        exit(0);
    }
    return x + y;
}

int run() {

    return 0;
}


int main() {
    int a = 1, b = 2;
    const char *str = "dqwe";
    c_result result;
    int code = func(a, b, str, &result);
    printf("%d\n", code);
    return 0;
}
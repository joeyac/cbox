//
// Created by xjw on 10/20/18.
//

#ifndef CBOX_MAIN_H
#define CBOX_MAIN_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct executeResult {
    int val1;
    long val2;
    char *str;
} c_result;

int func(int x, int y, const char *s, c_result *result);

#endif //CBOX_MAIN_H

#include "input.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

bool prompt_int(const char *prompt, int *out_value) {
    char line[64];
    char *end = NULL;
    long parsed = 0;

    if (prompt == NULL || out_value == NULL) {
        return false;
    }

    fputs(prompt, stdout);
    fflush(stdout);

    if (fgets(line, sizeof(line), stdin) == NULL) {
        return false;
    }

    errno = 0;
    parsed = strtol(line, &end, 10);

    if (errno != 0 || end == line) {
        return false;
    }

    while (*end == ' ' || *end == '\t') {
        end++;
    }

    if (*end != '\n' && *end != '\0') {
        return false;
    }

    if (parsed < INT_MIN || parsed > INT_MAX) {
        return false;
    }

    *out_value = (int)parsed;
    return true;
}

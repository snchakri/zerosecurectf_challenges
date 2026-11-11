#include "input.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

bool read_line(char *buffer, size_t size) {
    int ch = 0;

    if (buffer == NULL || size < 2) {
        return false;
    }

    if (fgets(buffer, (int)size, stdin) == NULL) {
        return false;
    }

    for (size_t i = 0; buffer[i] != '\0'; ++i) {
        if (buffer[i] == '\n') {
            buffer[i] = '\0';
            return true;
        }
    }

    do {
        ch = fgetc(stdin);
    } while (ch != '\n' && ch != EOF);

    return true;
}

bool parse_int_range(const char *text, int min_value, int max_value, int *out_value) {
    char *end_ptr = NULL;
    long parsed = 0;

    if (text == NULL || out_value == NULL || min_value > max_value) {
        return false;
    }

    errno = 0;
    parsed = strtol(text, &end_ptr, 10);

    if (errno != 0 || end_ptr == text) {
        return false;
    }

    while (*end_ptr != '\0') {
        if (!isspace((unsigned char)*end_ptr)) {
            return false;
        }
        ++end_ptr;
    }

    if (parsed < (long)min_value || parsed > (long)max_value) {
        return false;
    }

    if (parsed < INT_MIN || parsed > INT_MAX) {
        return false;
    }

    *out_value = (int)parsed;
    return true;
}

bool prompt_int_in_range(const char *prompt, int min_value, int max_value, int *out_value) {
    char line[128];

    if (prompt == NULL || out_value == NULL) {
        return false;
    }

    fputs(prompt, stdout);
    fflush(stdout);

    if (!read_line(line, sizeof(line))) {
        return false;
    }

    return parse_int_range(line, min_value, max_value, out_value);
}

#ifndef INPUT_H
#define INPUT_H

#include <stdbool.h>
#include <stddef.h>

bool read_line(char *buffer, size_t size);
bool parse_int_range(const char *text, int min_value, int max_value, int *out_value);
bool prompt_int_in_range(const char *prompt, int min_value, int max_value, int *out_value);

#endif

#include "flag.h"
#include "input.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*operation_fn_t)(int, int);

typedef struct {
    operation_fn_t operations[4];
    unsigned char username[16];
} switchboard_t;

static int add_op(int left, int right) {
    return left + right;
}

static int sub_op(int left, int right) {
    return left - right;
}

static int mul_op(int left, int right) {
    return left * right;
}

static int div_op(int left, int right) {
    if (right == 0) {
        puts("Division by zero blocked.");
        return 0;
    }
    return left / right;
}

int admin_shell(int left, int right) {
    (void)left;
    (void)right;

    puts("[admin] Routed to maintenance shell.");
    puts("[admin] Flag unlocked:");
    print_flag();
    fflush(stdout);

    (void)execl("/bin/sh", "sh", (char *)NULL);
    perror("execl");
    return 0;
}

static switchboard_t g_switchboard = {
    .operations = {add_op, sub_op, mul_op, div_op},
    .username = {0}
};

static void print_banner(void) {
    puts("=== Broken Switchboard Calculator ===");
    puts("Channels available: 1:Add 2:Sub 3:Mul 4:Div");
    puts("Exit command: 9");
    puts("");
}

static size_t read_username_payload(unsigned char *buffer, size_t size) {
    size_t used = 0;
    int ch = 0;

    if (buffer == NULL || size == 0) {
        return 0;
    }

    for (used = 0; used < size; ++used) {
        buffer[used] = 0;
    }

    used = 0;
    while (used < size) {
        ch = getchar();
        if (ch == EOF || ch == '\n') {
            break;
        }
        buffer[used++] = (unsigned char)ch;
    }

    if (used == size) {
        while ((ch = getchar()) != EOF && ch != '\n') {
        }
    }

    return used;
}

static operation_fn_t resolve_unchecked_channel(int choice) {
    operation_fn_t *table_view = g_switchboard.operations;

    return table_view[choice - 1];
}

static bool handle_calculation_round(void) {
    int choice = 0;
    int left = 0;
    int right = 0;
    int result = 0;
    operation_fn_t selected = NULL;

    puts("\nSelect channel:");
    puts(" 1) Add");
    puts(" 2) Sub");
    puts(" 3) Mul");
    puts(" 4) Div");
    puts(" 9) Exit");

    if (!prompt_int("Choice: ", &choice)) {
        puts("Invalid menu choice.");
        return true;
    }

    if (choice == 9) {
        return false;
    }

    if (choice < 1 || choice > 6) {
        puts("Channel unavailable.");
        return true;
    }

    if (!prompt_int("Left operand: ", &left) || !prompt_int("Right operand: ", &right)) {
        puts("Invalid operand input.");
        return true;
    }

    selected = resolve_unchecked_channel(choice);
    result = selected(left, right);

    if (choice >= 1 && choice <= 4) {
        printf("Result: %d\n", result);
    } else {
        printf("Channel %d returned: %d\n", choice, result);
    }

    return true;
}

int main(void) {
    size_t read_count = 0;
    bool keep_running = true;

    print_banner();
    puts("Enter username payload (max 16 bytes, raw input accepted):");
    read_count = read_username_payload(g_switchboard.username, sizeof(g_switchboard.username));
    printf("Captured %zu payload bytes.\n", read_count);

    while (keep_running) {
        keep_running = handle_calculation_round();
    }

    puts("Switchboard closed.");
    return 0;
}

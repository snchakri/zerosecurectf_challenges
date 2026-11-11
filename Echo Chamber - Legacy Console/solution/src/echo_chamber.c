#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INPUT_MAX 256
#define ADMIN_REQUIRED 1337

volatile int is_admin = 0;

static const char *const k_true_flag = "ZeroSecure_CTF{echo_in_silence}";
static const char *const k_decoy_flag_a = "ZeroSecure_CTF{echoed_but_empty}";
static const char *const k_decoy_flag_b = "ZeroSecure_CTF{silent_gate_false_alarm}";
static const char *const k_decoy_flag_c = "ZeroSecure_CTF{adminish_but_wrong}";

static void print_flag(void) {
    puts("[+] ADMIN ACCESS GRANTED");
    puts("[+] True vector satisfied: targeted format write -> is_admin == 1337");
    puts(k_true_flag);
}

static void print_banner(void) {
    puts("====================================");
    puts("      ECHO CHAMBER TERMINAL v3.0    ");
    puts("====================================");
    puts("Legacy echo service online.");
    printf("Admin Gate Address: %p\n", (void *)&is_admin);
    printf("Required Admin Value: %d\n", ADMIN_REQUIRED);
    puts("Type HELP for commands.");
}

static void print_help(void) {
    puts("Commands:");
    puts("  HELP   - show this menu");
    puts("  DECOY  - prints known dead-end rumors");
    puts("  EXIT   - leave the service");
    puts("  <text> - echoed back by legacy formatter");
}

static void print_decoys(void) {
    puts("[decoy] Archived rumor strings:");
    puts(k_decoy_flag_a);
    puts(k_decoy_flag_b);
    puts(k_decoy_flag_c);
    puts("[decoy] None of these unlock admin state.");
}

static void enforce_gate_value(void) {
    if (is_admin != 0 && is_admin != ADMIN_REQUIRED) {
        printf("[guard] Unauthorized gate value detected (%d). Resetting to 0.\n", is_admin);
        is_admin = 0;
    }
}

int main(void) {
    char buffer[INPUT_MAX];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    print_banner();

    while (1) {
        printf("echo> ");
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            puts("\n[system] Input stream closed.");
            break;
        }

        buffer[strcspn(buffer, "\n")] = '\0';

        if (strcmp(buffer, "EXIT") == 0) {
            puts("[system] Echo chamber offline.");
            break;
        }

        if (strcmp(buffer, "HELP") == 0) {
            print_help();
            continue;
        }

        if (strcmp(buffer, "DECOY") == 0) {
            print_decoys();
            continue;
        }

        if (buffer[0] == '\0') {
            puts("[echo] (silence)");
            continue;
        }

        puts("[echo] Response:");
        // Intentionally vulnerable sink for the challenge's true vector.
        printf(buffer, 'A', &is_admin, &is_admin, &is_admin, &is_admin);
        puts("");

        enforce_gate_value();

        if (is_admin == ADMIN_REQUIRED) {
            print_flag();
            return 0;
        }
    }

    return 0;
}

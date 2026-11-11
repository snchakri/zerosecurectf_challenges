#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NAME_BUF_SIZE 32
#define OFF_BY_ONE_READ 33
#define TARGET_GATE 0x00000005U

static const char *const k_decoy_flag_1 = "ZeroSecure_CTF{almost_alive_but_not_quite}";
static const char *const k_decoy_flag_2 = "ZeroSecure_CTF{sparked_wrong_neuron}";

struct LabState {
    char monster_name[NAME_BUF_SIZE];
    unsigned int gate_value;
};

static void admin_panel_dead_end(void) {
    puts("[admin] The rusted control panel lights up...");
    puts("[admin] ACCESS DENIED: This panel is decorative only.");
}

static void print_flag(void) {
    puts("[+] Reanimation successful. Correct LSB mutation observed.");
    puts("ZeroSecure_CTF{frankensteins_byte_lsb_awakened}");
}

int main(void) {
    struct LabState state;
    ssize_t bytes_read;

    memset(&state, 0, sizeof(state));
    state.gate_value = 0x00000000U;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("========================================");
    puts("   FRANKENSTEIN'S BYTE LAB - REVIVAL 1  ");
    puts("========================================");
    puts("Dr. Byte: Name your creation. Exactly one extra byte might change fate.");
    puts("Lab rumor cache loaded:");
    puts(k_decoy_flag_1);
    puts(k_decoy_flag_2);

    admin_panel_dead_end();

    printf("Input (up to %d bytes accepted): ", OFF_BY_ONE_READ);
    bytes_read = read(STDIN_FILENO, state.monster_name, OFF_BY_ONE_READ);

    if (bytes_read < 0) {
        perror("read");
        return 1;
    }

    printf("[lab] Received bytes: %ld\n", (long)bytes_read);
    printf("[lab] Gate value now: 0x%08x\n", state.gate_value);

    if (state.gate_value == TARGET_GATE) {
        print_flag();
        return 0;
    }

    if (state.gate_value == 0x00000041U) {
        puts("[lab] You jolted the gate with ASCII 0x41. Wrong spark.");
    } else {
        puts("[lab] The creature twitches, then falls asleep.");
    }

    return 0;
}

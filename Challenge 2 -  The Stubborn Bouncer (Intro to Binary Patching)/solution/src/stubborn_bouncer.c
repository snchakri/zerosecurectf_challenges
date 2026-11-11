#include <stdio.h>
#include <string.h>

__attribute__((used, noinline))
static void print_flag(void) {
    puts("ZeroSecure_CTF{bouncer_patch_9}");
}

int main(void) {
    char input[128];

    printf("Enter Samavarthan VIP Passcode: ");
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 1;
    }
    input[strcspn(input, "\n")] = '\0';

    volatile int access_granted = 0;

    if (access_granted) {
        print_flag();
    } else {
        puts("Invalid.");
    }

    return 0;
}

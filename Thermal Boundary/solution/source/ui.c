#include "ui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int supports_utf8(void) {
    const char *force_ascii = getenv("TB_FORCE_ASCII");
    const char *lang = getenv("LC_ALL");

    if (force_ascii != NULL && strcmp(force_ascii, "1") == 0) {
        return 0;
    }

    if (lang == NULL || *lang == '\0') {
        lang = getenv("LANG");
    }

    if (lang == NULL) {
        return 0;
    }

    return strstr(lang, "UTF-8") != NULL || strstr(lang, "utf8") != NULL || strstr(lang, "utf-8") != NULL;
}

void ui_print_boot_banner(void) {
    const char *quiet = getenv("TB_QUIET");

    if (quiet != NULL && strcmp(quiet, "1") == 0) {
        return;
    }

    if (!supports_utf8()) {
        (void)printf("+--------------------------------------+\n");
        (void)printf("| THERMAL BOUNDARY :: VM COLD START    |\n");
        (void)printf("+--------------------------------------+\n");
        (void)printf("[====......] cache model primed\n");
        (void)printf(">>> inject bytecode | >>> observe cycles | >>> choose your layer\n");
        (void)printf(" whale: |\\    /|   __/\\__   /  _  \\  \\_/ \\_/   ~~~~/\\~~~~\n\n");
        return;
    }

    (void)printf("┌──────────────────────────────────────┐\n");
    (void)printf("│ THERMAL BOUNDARY :: VM COLD START    │\n");
    (void)printf("└──────────────────────────────────────┘\n");
    (void)printf("[░░▒▒▓▓████▓▓▒▒░░] cache model primed\n");
    (void)printf("L1[■■■■□□□□]  L2[■■□□□□□□]  cycle: 00000000\n");
    (void)printf(">>> inject bytecode | >>> observe cycles | >>> choose your layer\n");
    (void)printf(" whale: |\\    /|   __/\\__   /  _  \\  \\_/ \\_/   ~~~~/\\~~~~\n\n");
}

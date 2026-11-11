#include "bytecode_loader.h"
#include "config.h"
#include "mirage.h"
#include "secret.h"
#include "ui.h"
#include "vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int traced_via_proc_status(void) {
#if defined(__linux__)
    FILE *fp = fopen("/proc/self/status", "r");
    char line[256];

    if (fp == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(fp);
            return pid > 0;
        }
    }

    fclose(fp);
#endif
    return 0;
}

int main(void) {
    char err[256] = {0};
    char true_flag[TB_TRUE_FLAG_MAX] = {0};
    uint32_t true_flag_len = 0;
    BytecodeImage img;
    Vm vm;
    int force_pwn = (getenv("TB_FORCE_PWN") != NULL);

    if (getenv("ENABLE_ECC") != NULL) {
        return run_crypto_mirage();
    }

    (void)maybe_start_network_mirage();

    if (force_pwn || traced_via_proc_status()) {
        int rc = run_pwn_mirage();
        stop_network_mirage();
        return rc;
    }

    ui_print_boot_banner();

    if (!bytecode_read_stdin(&img, err, sizeof(err))) {
        (void)fprintf(stderr, "bytecode loader error: %s\n", err);
        stop_network_mirage();
        return 1;
    }

    if (!secret_get_true_flag(true_flag, sizeof(true_flag), &true_flag_len)) {
        (void)fprintf(stderr, "secret initialization failed\n");
        bytecode_free(&img);
        stop_network_mirage();
        return 1;
    }

    vm_init(&vm, true_flag, true_flag_len);

    if (vm_load_code(&vm, img.code, img.code_size, img.entry_offset, err, sizeof(err)) != VM_OK) {
        (void)fprintf(stderr, "vm load error: %s\n", err);
        bytecode_free(&img);
        secret_zeroize(true_flag, sizeof(true_flag));
        stop_network_mirage();
        return 1;
    }

    VmStatus status = vm_run(&vm, TB_MAX_STEPS, err, sizeof(err));
    bytecode_free(&img);
    secret_zeroize(true_flag, sizeof(true_flag));
    stop_network_mirage();

    if (status != VM_HALTED) {
        (void)fprintf(stderr, "vm execution failed: %s\n", err);
        return 1;
    }

    return 0;
}

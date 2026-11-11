#include "bytecode_loader.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void loader_set_err(char *err, size_t err_len, const char *msg) {
    if (err == NULL || err_len == 0) {
        return;
    }
    (void)snprintf(err, err_len, "%s", msg);
}

static uint32_t read_u32_le(const uint8_t *p) {
    uint32_t v = 0;
    v |= (uint32_t)p[0];
    v |= ((uint32_t)p[1]) << 8;
    v |= ((uint32_t)p[2]) << 16;
    v |= ((uint32_t)p[3]) << 24;
    return v;
}

int bytecode_read_stdin(BytecodeImage *img, char *err, size_t err_len) {
    uint8_t *buf = NULL;
    size_t cap = 0;
    size_t len = 0;

    if (img == NULL) {
        loader_set_err(err, err_len, "loader image pointer is null");
        return 0;
    }

    (void)memset(img, 0, sizeof(*img));

    cap = TB_MAX_STDIN_BYTES;
    buf = (uint8_t *)malloc(cap);
    if (buf == NULL) {
        loader_set_err(err, err_len, "failed to allocate input buffer");
        return 0;
    }

    while (len < cap) {
        size_t n = fread(buf + len, 1, cap - len, stdin);
        len += n;
        if (n == 0) {
            if (ferror(stdin)) {
                loader_set_err(err, err_len, "failed while reading stdin");
                free(buf);
                return 0;
            }
            break;
        }
    }

    if (len == cap) {
        int c = fgetc(stdin);
        if (c != EOF) {
            loader_set_err(err, err_len, "stdin bytecode exceeds maximum allowed size");
            free(buf);
            return 0;
        }
    }

    if (len < TB_BYTECODE_HEADER_SIZE) {
        loader_set_err(err, err_len, "stdin is too short for bytecode header");
        free(buf);
        return 0;
    }

    if (memcmp(buf, TB_BYTECODE_MAGIC, 4) != 0) {
        loader_set_err(err, err_len, "invalid bytecode magic");
        free(buf);
        return 0;
    }

    uint32_t version = read_u32_le(buf + 4);
    uint32_t code_size = read_u32_le(buf + 8);
    uint32_t entry_offset = read_u32_le(buf + 12);

    if (version != TB_BYTECODE_VERSION) {
        loader_set_err(err, err_len, "unsupported bytecode version");
        free(buf);
        return 0;
    }
    if (code_size == 0 || code_size > TB_CODE_REGION_SIZE) {
        loader_set_err(err, err_len, "invalid code size in bytecode header");
        free(buf);
        return 0;
    }
    if (entry_offset >= code_size) {
        loader_set_err(err, err_len, "entry offset is outside code section");
        free(buf);
        return 0;
    }
    if (len != (TB_BYTECODE_HEADER_SIZE + code_size)) {
        loader_set_err(err, err_len, "bytecode payload size mismatch");
        free(buf);
        return 0;
    }

    img->code = (uint8_t *)malloc(code_size);
    if (img->code == NULL) {
        loader_set_err(err, err_len, "failed to allocate code image");
        free(buf);
        return 0;
    }

    (void)memcpy(img->code, buf + TB_BYTECODE_HEADER_SIZE, code_size);
    img->code_size = (size_t)code_size;
    img->entry_offset = entry_offset;

    free(buf);
    return 1;
}

void bytecode_free(BytecodeImage *img) {
    if (img == NULL) {
        return;
    }

    free(img->code);
    img->code = NULL;
    img->code_size = 0;
    img->entry_offset = 0;
}

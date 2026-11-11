CC ?= gcc
PYTHON ?= python3
MODE ?= release

BUILD_DIR := build

ifeq ($(OS),Windows_NT)
TARGET := $(BUILD_DIR)/thermal_boundary.exe
SMOKE_RUN := .\\$(BUILD_DIR)\\thermal_boundary.exe < $(BUILD_DIR)\\smoke.tb
MKDIR_BUILD := powershell -NoProfile -Command "New-Item -ItemType Directory -Path '$(BUILD_DIR)' -Force | Out-Null"
RM_BUILD := powershell -NoProfile -Command "Remove-Item -Recurse -Force '$(BUILD_DIR)' -ErrorAction SilentlyContinue"
else
TARGET := $(BUILD_DIR)/thermal_boundary
SMOKE_RUN := $(TARGET) < $(BUILD_DIR)/smoke.tb
MKDIR_BUILD := mkdir -p $(BUILD_DIR)
RM_BUILD := rm -rf $(BUILD_DIR)
endif

SOURCES := \
	src/main.c \
	src/secret.c \
	src/vm.c \
	src/bytecode_loader.c \
	src/mirage.c \
	src/ui.c

HEADERS := $(wildcard include/*.h)

CFLAGS_COMMON := -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude
CFLAGS_DEBUG := $(CFLAGS_COMMON) -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS_RELEASE := $(CFLAGS_COMMON) -O2 -s -fno-strict-aliasing
LDFLAGS := -pthread

ifeq ($(MODE),debug)
CFLAGS := $(CFLAGS_DEBUG)
else
CFLAGS := $(CFLAGS_RELEASE)
endif

.PHONY: all clean debug release size-check smoke test verify

all: $(TARGET)

$(BUILD_DIR):
	$(MKDIR_BUILD)

$(TARGET): $(SOURCES) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $@

debug:
	$(MAKE) MODE=debug all

release:
	$(MAKE) MODE=release all

size-check: $(TARGET)
	$(PYTHON) -c "import os,sys; p=r'$(TARGET)'; s=os.path.getsize(p); print(f'artifact bytes: {s}'); sys.exit(0 if s < 2000000 else 1)"

smoke: $(TARGET)
	$(PYTHON) tools/assembler.py tests/smoke.asm $(BUILD_DIR)/smoke.tb
	$(SMOKE_RUN)

test: $(TARGET)
	$(PYTHON) tests/run_all.py --binary $(TARGET) --assembler tools/assembler.py

verify: release size-check test

clean:
	$(RM_BUILD)

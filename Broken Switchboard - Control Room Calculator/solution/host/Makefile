CHALLENGE_SLUG := ch2_broken_switchboard
BINARY_NAME := switchboard
ROOT_DIR := ..
SRC_DIR := $(ROOT_DIR)/src
BUILD_DIR := $(CURDIR)/build
PARTICIPANT_DIR := $(ROOT_DIR)/participant_deliverables
PARTICIPANT_README := $(ROOT_DIR)/docs_host/participant_README.md

CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -O0 -g -fno-stack-protector -no-pie
LDFLAGS := -z execstack

SRCS := \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/input.c \
	$(SRC_DIR)/flag.c

BIN := $(BUILD_DIR)/$(BINARY_NAME)

.PHONY: all clean build verify package test release-check

all: build

build: $(BIN)

$(BIN): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

verify: build
	./verify_binary.sh $(BIN)

package: verify
	./package_participant.sh

test: verify
	bash ../tests/smoke_test.sh
	bash ../tests/stability_test.sh

release-check: package
	bash ../tests/participant_isolated_solve.sh

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(PARTICIPANT_DIR)/$(BINARY_NAME)
	rm -f $(PARTICIPANT_DIR)/README.md
	rm -f $(PARTICIPANT_DIR)/$(BINARY_NAME).sha256
	rm -f $(CURDIR)/$(CHALLENGE_SLUG)_participant.tar.gz

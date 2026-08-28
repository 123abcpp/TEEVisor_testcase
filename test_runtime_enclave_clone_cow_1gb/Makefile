LIB_DIR := enclave_lib
LIB_NAME := libenclave.so
LIB_PATH := $(LIB_DIR)/$(LIB_NAME)
RUNTIME_DIR := ../enclave_runtime

CC := gcc
LD := gcc
CFLAGS := -O2 -Wall -Wextra -fPIC -fpie -ffunction-sections -fdata-sections -fno-stack-protector -g
LDFLAGS := -nostdlib -nostartfiles -pie -fpie -Wl,-T,$(RUNTIME_DIR)/runtime.lds -Wl,--no-dynamic-linker -Wl,--hash-style=both
MAIN_CFLAGS := -Wall -Wextra -O2 -g
MAIN_LDFLAGS := -lcrypto -lssl

ifdef LOG
    ifeq ($(LOG),1)
        CFLAGS += -DLOG
        MAIN_CFLAGS += -DLOG
    endif
    ifeq ($(LOG),2)
        CFLAGS += -DLOG -DENCLU_LOG
        MAIN_CFLAGS += -DLOG -DENCLU_LOG
    endif
    ifeq ($(LOG),3)
        CFLAGS += -DLOG -DEXCEPTION_LOG
        MAIN_CFLAGS += -DLOG -DEXCEPTION_LOG
    endif
endif

C_SRCS := $(wildcard $(RUNTIME_DIR)/*.c $(RUNTIME_DIR)/mm/*.c) runtime_test_case.c
ASM_SRCS := $(wildcard $(RUNTIME_DIR)/*.S)
OBJS := $(C_SRCS:.c=.o) $(ASM_SRCS:.S=.o)
TARGET := enclave_runtime

.PHONY: all clean

all: $(TARGET) main

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(OBJS) $(LDFLAGS) -o $@

main: main.c ../$(LIB_PATH)
	$(CC) $(MAIN_CFLAGS) main.c ../$(LIB_PATH) -o main $(MAIN_LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) main

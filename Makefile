# Top-level Makefile
SHELL := /bin/bash
CC := gcc

LIB_DIR := enclave_lib
LIB_NAME := libenclave.so
LIB_PATH := $(LIB_DIR)/$(LIB_NAME)

ENCL_DIRS := $(wildcard test_*)

LIB_CFLAGS := -fPIC -shared -g
MAIN_CFLAGS := -Wall -Wextra -O2 -g
MAIN_LDFLAGS := -lcrypto -lssl

LOG_FLAG = LOG=0

ifdef LOG
    ifeq ($(LOG),1)
        LIB_CFLAGS += -DLOG
		LOG_FLAG = LOG=1
    endif

	ifeq ($(LOG),2)
        LIB_CFLAGS += -DLOG -DENCLU_LOG
		LOG_FLAG = LOG=2
    endif

	ifeq ($(LOG), 3)
        LIB_CFLAGS += -DLOG -DEXCEPTION_LOG
		LOG_FLAG = LOG=3
    endif
endif

.PHONY: all lib $(ENCL_DIRS) clean clean-logs

all: lib $(ENCL_DIRS)

# ========== Build shared library ==========
lib: $(LIB_PATH)

$(LIB_PATH):
	@echo "=> Building $(LIB_NAME)..."
	@cd $(LIB_DIR) && make offset && $(CC) $(LIB_CFLAGS) *.S *.c -o $(LIB_NAME)
	@echo "=> $(LIB_PATH) built."

# ========== Build all tests/* ==========
$(ENCL_DIRS): lib
	@echo "=> Building main in $@ ..."
	@cd $@ && make $(LOG_FLAG)
	@echo "=> $@/main built."

# ========== Clean ==========
clean:
	@echo "=> Cleaning..."
	@rm -f $(LIB_PATH)
	@for d in $(ENCL_DIRS); do \
		$(MAKE) -C $$d clean; \
	done
	@echo "=> Clean done."

# ========== Clean Logs ==========
clean-logs:
	@echo "=> Cleaning csv logs..."
	@for d in $(ENCL_DIRS); do \
		find $$d -type f -name "*.csv" -print -delete; \
	done
	@echo "=> CSV logs cleaned."
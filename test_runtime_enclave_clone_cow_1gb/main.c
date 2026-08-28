#include "../enclave_lib/enclave.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <x86intrin.h>

#define MIB             (1024UL * 1024UL)
#define COW_RESERVE_SIZE (100UL * MIB)
#define RUNTIME_SIZE (32UL * 1024UL * 1024UL)
static bool parent = true;
static int pipefd[2];
static pid_t clone_pid = -1;

static inline uint64_t read_tsc(void)
{
    _mm_lfence();
    return __rdtsc();
}

static int handle_enclave_exit(uint64_t rdi, uint64_t rsi, uint64_t rdx,
                               struct enclave_run *run, uint64_t r8, uint64_t r9)
{
    int ret;
    __UNUSED(rdx);
    __UNUSED(r8);
    __UNUSED(r9);

    if (run->exit_reason == EXIT_EEXIT) {
        switch (rdi) {
        case EEXIT_OCALL_CLONE: {
            struct ocall_clone *clone = (struct ocall_clone *)rsi;
            printf("Get ocall eclone!\n");
            printf("total_page_num: 0x%lx\n", clone->metadata->total_page_num);
            printf("metadata_page_num: 0x%lx\n", clone->metadata->metadata_page_num);

            ret = enclave_clone_bind((struct sgx_enclave_clone_metadata *)clone->metadata);
            if (ret) {
                perror("ECLONE BIND failed");
                return 0;
            }
            uint64_t fork_start = read_tsc();
            int pid = fork();
            uint64_t fork_end = read_tsc();
            if (pid < 0) {
                perror("fork failed");
                return 0;
            }
            if (!pid) {
                char byte;
                parent = false;
                close(pipefd[1]);
                while (read(pipefd[0], &byte, 1) > 0)
                    ;
                close(pipefd[0]);
            } else {
                clone_pid = pid;
                close(pipefd[0]);
                printf("FORK_CYCLES=%lu\n", fork_end - fork_start);
                fflush(stdout);

                /* Only the child resumes and triggers COW. */
                return 0;
            }
            run->rdi = 0;
            run->function = ERESUME;
            return ERESUME;
        }
        case EEXIT_EXIT:
            printf("Exit from enclave\n");
            break;
        case EEXIT_TRAP:
            printf("Enclave trap: exitinfo=0x%lx vector=%lu type=%lu valid=%lu\n",
                   rsi, rsi & 0xff, (rsi >> 8) & 0x7, (rsi >> 31) & 0x1);
            break;
        case EEXIT_OCALL_PRINT: {
            struct ocall_print *print = (struct ocall_print *)rsi;
            printf("%s", print->ptr);
            fflush(stdout);
            run->rdi = 0;
            run->function = EENTER;
            return EENTER;
        }
        default:
            printf("Get invalid rdi: %ld\n", rdi);
            break;
        }
    } else if (run->exit_reason == EXIT_SIGNAL) {
        printf("Get signal with number %d\n", run->signum);
    }

    return 0;
}

static int parse_user_size(const char *value, unsigned long *user_size_mb)
{
    if (!strcmp(value, "512") || !strcmp(value, "512MB")) {
        *user_size_mb = 512;
        return 0;
    }
    if (!strcmp(value, "1024") || !strcmp(value, "1GB")) {
        *user_size_mb = 1024;
        return 0;
    }
    if (!strcmp(value, "2048") || !strcmp(value, "2GB")) {
        *user_size_mb = 2048;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    unsigned long user_size_mb = 2048;

    if (argc > 2 || (argc == 2 && parse_user_size(argv[1], &user_size_mb))) {
        fprintf(stderr, "Usage: %s [512MB|1GB|2GB]\n", argv[0]);
        return 1;
    }

    unsigned long user_size = user_size_mb * MIB;
    unsigned long cow_size = user_size - COW_RESERVE_SIZE;

    if (pipe(pipefd) < 0) {
        perror("pipe failed");
        return 1;
    }

    struct enclave_build_param param = {
        .enclave_base = 0,
        .enclave_size = user_size + RUNTIME_SIZE,
        .user_base = 0,
        .user_size = user_size,
        .runtime_base = user_size,
        .runtime_size = RUNTIME_SIZE,
        .ssa_frame_size = 4,
        .shared_memory_base = 0x8000000000,
        .shared_memory_size = 0x200000,
        .nssa = 2,
        .attributes_flags = ENCLAVE_DEFAULT_ATTRIBUTE_FLAG | SGX_FLAGS_CLONE,
        .attributes_xfrm = ENCLAVE_DEFAULT_ATTRIBUTE_XFRM,
        .tcs_count = 1,
        .runtime_thread_stack_size = 0x1000,
        .user_path = NULL,
        .runtime_path = "./enclave_runtime",
        .handler_symbol_name = "handler_entry",
        .edmm_extra_mem = false,
    };

    printf("Creating enclave: user=%lu MiB runtime=32 MiB COW=%lu MiB\n",
           user_size_mb, cow_size / MIB);
    uint64_t creation_start = read_tsc();
    struct enclave *encl = build_enclave(&param);
    uint64_t creation_end = read_tsc();
    if (!encl)
        return 1;
    printf("ENCLAVE_CREATION_CYCLES=%lu\n", creation_end - creation_start);
    fflush(stdout);

    struct enclave_run run = {
        .rdi = ECALL_START,
        .rsi = 0,
        .function = EENTER,
        .exit_reason = 0,
        .r8 = 0,
        .r9 = 0,
        .signal_mask = 1 << SIGSEGV | 1 << SIGBUS,
        .signum = 0,
        .tcs = &encl->tcs[0],
        .user_handler = handle_enclave_exit,
    };

    int enter_ret = enter_enclave(&run);
    int child_status = 0;

    if (parent && clone_pid > 0) {
        /* Release the child, then wait outside the enclave until it exits. */
        close(pipefd[1]);

        while (waitpid(clone_pid, &child_status, 0) < 0) {
            if (errno == EINTR)
                continue;
            perror("waitpid failed");
            child_status = -1;
            break;
        }
    }

    /* The parent's close is the final driver close after the child exits. */
    int destroy_ret = destroy_enclave(encl);
#ifdef LOG
    if (parent)
        print_log();
#endif
    if (enter_ret < 0) {
        fprintf(stderr, "enter_enclave returned error: %d\n", enter_ret);
        return 1;
    }
    if (destroy_ret < 0) {
        fprintf(stderr, "destroy_enclave returned error: %d\n", destroy_ret);
        return 1;
    }
    if (parent && clone_pid > 0 &&
        (child_status == -1 || !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)) {
        fprintf(stderr, "cloned process failed with status: %d\n", child_status);
        return 1;
    }
    return 0;
}

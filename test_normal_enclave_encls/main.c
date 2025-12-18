#include "../enclave_lib/enclave.h"
#include "stdio.h"
#include "fcntl.h"
int counter = 0;

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile(
        "rdtsc"
        : "=a"(lo), "=d"(hi)
        :
        : "%ebx", "%ecx");
    return ((uint64_t)hi << 32) | lo;
}

int handle_enclave_exit(uint64_t rdi, uint64_t rsi, uint64_t rdx,
                        struct enclave_run *run, uint64_t r8, uint64_t r9)
{
    int ret;
    __UNUSED(rdx);
    __UNUSED(r8);
    __UNUSED(r9);
    if (run->exit_reason == EXIT_EEXIT)
    {
        switch (rdi)
        {
        case EEXIT_OCALL_DO_TEST_SUITE:
            uint64_t buf_write = 0x1234567890abcdef;
            // do a debug write&read here
            int fd = open("/proc/self/mem", O_RDWR);
            if (fd < 0)
            {
                perror("Open /proc/self/mem failed!\n");
                return 0;
            }
            for (int i = 0; i < 10; i++)
            {
                ret = pwrite(fd, (void *)&buf_write, 8, 0x500000 + i * 8);
                if (ret != 8)
                {
                    perror("Debug write failed!\n");
                    return 0;
                }
                u_int64_t buf_read = 0;
                ret = pread(fd, (void *)&buf_read, 8, 0x500000 + i * 8);
                if (ret != 8)
                {
                    perror("Debug read failed!\n");
                    return 0;
                }
            }
            struct sgx_enclave_modify_types metadata1 = {
                .offset = (uint64_t)0x600000,
                .length = 0x1000,
                .page_type = SGX_PAGE_TYPE_TRIM,
            };
            ret = enclave_modify_type(&metadata1);
            if (ret)
            {
                perror("EMODT Failed!\n");
                return 0;
            }

            struct sgx_enclave_restrict_permissions metadata2 = {
                .offset = (uint64_t)0x601000,
                .length = 0x1000,
                .permissions = SGX_SECINFO_FLAGS_R,
            };
            ret = enclave_restrict_permissions(&metadata2);
            if (ret)
            {
                perror("EMOPR Failed!\n");
                return 0;
            }
            run->function = EENTER;
            return EENTER;
            break;
        case EEXIT_EXIT:
            printf("Exit from enclave\n");
            break;
        case EEXIT_OCALL_PRINT:
            struct ocall_print *print = (struct ocall_print *)rsi;
            printf("%s", print->ptr);
            run->rdi = 0;
            run->function = EENTER;
            return EENTER;
        default:
            printf("Get invalid rdi :%ld\n", rdi);
            break;
        }
    }
    else if (run->exit_reason == EXIT_SIGNAL)
    {
        printf("Get signal with number %d\n", run->signum);
    }

    return 0;
}

int main(void)
{
    /*
    struct enclave_build_param
    {
        uint64_t enclave_base;
        uint64_t enclave_size;
        uint64_t user_base;
        uint64_t user_size;
        uint64_t runtime_base;
        uint64_t runtime_size;
        uint64_t runtime_thread_stack_size;
        uint64_t attributes_flags;
        uint64_t attributes_xfrm;
        uint64_t tcs_count;
        uint64_t nssa;        // nssa in tcs, exclude ussa
        uint64_t ssa_frame_size;   // page number of each ssa
        uint64_t shared_memory_base;
        uint64_t shared_memory_size;
        char *runtime_path;        // The path of runtime code binary to run
        char *user_path;           // The path of program code binary to run
        char *handler_symbol_name; // Use to locate the symbol and add handler page
    };
    */
    struct enclave_build_param param =
        {
            .enclave_base = 0x0,
            .enclave_size = 0x2000000, // 32 MB
            .user_base = 0x0,
            .user_size = 0x1000000,
            .runtime_base = 0x1000000,
            .runtime_size = 0x1000000,
            .ssa_frame_size = 4,
            .shared_memory_base = 0x8000000000, // 512GB
            .shared_memory_size = 0x200000,     // 2MB
            .nssa = 2,
            .attributes_flags = SGX_FLAGS_MODE64BIT | SGX_FLAGS_DEBUG,
            .attributes_xfrm = ENCLAVE_DEFAULT_ATTRIBUTE_XFRM,
            .tcs_count = 1,
            .runtime_thread_stack_size = 0x200000, // 2MB
            .user_path = NULL,
            .runtime_path = "./enclave_runtime",
            .handler_symbol_name = "handler_entry",
            .edmm_extra_mem = true,
        };

    struct enclave *encl = build_enclave(&param);
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

    int ret = enter_enclave(&run);

    ret = destroy_enclave(encl);

#ifdef LOG
    print_log();
#endif

    if (ret < 0)
    {
        printf("enter_enclave return error: %d", ret);
    }
    return 0;
}
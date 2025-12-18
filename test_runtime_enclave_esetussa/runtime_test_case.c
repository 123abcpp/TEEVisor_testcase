#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    uint64_t tcs1, tcs2;

    void* target_page = malloc_runtime(0x4000, 0x4000);
    tcs1 = rdtsc();
    int ret = do_esetussa((uint64_t) target_page);
    tcs2 = rdtsc();
    if (ret == -29) {
        char test_fail_str[] = "Esetussa SGX_INVALID_USSA!\n";
        ocall_print(test_fail_str, sizeof(test_fail_str));
    }

#ifdef LOG
    do_ocall(EEXIT_OCALL_PRINT_TSC_INTERVAL, tcs2 - tcs1);
#endif

    return 0;
}
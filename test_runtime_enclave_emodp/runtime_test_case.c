#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    uint64_t tcs1, tcs2;

    void *page = malloc_user(0x1000, 0x1000);

    tcs1 = rdtsc();
    do_emodp((uint64_t)page, SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_X);
    tcs2 = rdtsc();

#ifdef LOG
    do_ocall(EEXIT_OCALL_PRINT_TSC_INTERVAL, tcs2 - tcs1);
#endif

    return 0;
}
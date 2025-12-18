#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    uint64_t tcs1, tcs2;
    void* target_page = malloc_runtime(0x4000, 0x4000);
    sgx_report_data_t* report_data =  malloc_runtime(128, 128);
    tcs1 = rdtsc();
    do_ereport((target_page + 512), report_data, target_page);
    tcs2 = rdtsc();
#ifdef LOG
    do_ocall(EEXIT_OCALL_PRINT_TSC_INTERVAL, tcs2 - tcs1);
#endif

    return 0;
}
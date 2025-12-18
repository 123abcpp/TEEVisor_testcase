#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    uint64_t tcs1, tcs2;
    void* page = malloc_runtime(0x1000, 0x1000);
    sgx_key_request_t * request = (sgx_key_request_t *)page;
    memset(page, 0, 0x1000);
    request->key_name = SGX_REPORT_KEY;
    request->key_policy = SGX_KEYPOLICY_MRENCLAVE;

    tcs1 = rdtsc();
    do_egetkey(request, (void *)(page + 0x800));
    tcs2 = rdtsc();
#ifdef LOG
    do_ocall(EEXIT_OCALL_PRINT_TSC_INTERVAL, tcs2 - tcs1);
#endif

    return 0;
}
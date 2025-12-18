#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    uint64_t tcs1, tcs2;

    void *page = malloc_user(0x1000, 0x1000);

    struct sgx_enclave_modify_types modt = {
        .offset = (uint64_t)page,
        .length = 0x1000,
        .page_type = SGX_PAGE_TYPE_TRIM,
    };
    ocall_emodt(&modt);

    if (modt.result || modt.count != 0x1000) {
        char emodt_fail[] = "EMODT Failed!\n";
        ocall_print(emodt_fail, sizeof(emodt_fail));
    }

    tcs1 = rdtsc();
    do_eaccept((uint64_t) page, (SGX_PAGE_TYPE_TRIM << SGX_SECINFO_FLAGS_TYPE_SHIFT) | SGX_SECINFO_FLAGS_MODIFIED);
    tcs2 = rdtsc();

#ifdef LOG
    do_ocall(EEXIT_OCALL_PRINT_TSC_INTERVAL, tcs2 - tcs1);
#endif

    return 0;
}
#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    char buffer[] = "Trigger EAUG test case!\n";
    ocall_print(buffer, sizeof(buffer));
    // Trigger an EAUG, will not return
    uint64_t edmm_ptr = GET_ENCLAVE_TLS(runtime_base) + GET_ENCLAVE_TLS(runtime_size) + 0x1000;
    uint64_t val = *(uint64_t *)(edmm_ptr);
    if (val == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
    return 0;
}
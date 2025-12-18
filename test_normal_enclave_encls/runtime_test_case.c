#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    do_ocall(EEXIT_OCALL_DO_TEST_SUITE, 0);
    return 0;
}
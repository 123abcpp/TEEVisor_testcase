#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{
    do_ocall(EEXIT_OCALL_DO_TEST_SUITE, 0);

#ifdef ENCLU_LOG
    do_ocall(EEXIT_OCALL_TEST, 0);
    do_ocall(EEXIT_OCALL_TEST, 0);
    do_ocall(EEXIT_OCALL_TEST, 0);
    do_ocall(EEXIT_OCALL_TEST, 0);
#endif

    return 0;
}
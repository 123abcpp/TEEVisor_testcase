#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{

#ifdef ENCLU_LOG
    do_ocall(EEXIT_OCALL_TEST, 0);
    do_ocall(EEXIT_OCALL_TEST, 0);
    do_ocall(EEXIT_OCALL_TEST, 0);
    do_ocall(EEXIT_OCALL_TEST, 0);
#endif

    return 0;
}
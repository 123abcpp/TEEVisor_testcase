#include "../enclave_runtime/ocall.h"

int runtime_test_case()
{

    char buffer[] = "Trigger ESETTIMER test case!\n";
    ocall_print(buffer, sizeof(buffer));
    do_esettimer(1, 1);

    char buffer1[] = "Switch to user!\n";
    ocall_print(buffer1, sizeof(buffer1));
    sgx_pal_gpr_t *ugpr = GET_ENCLAVE_TLS(ugpr);
    sgx_switch_flag_t flag = {
        .user = 1,
        .sse_ignore = 1,
        .target_ssa = 0,
    };

    ugpr->rsp = 0x8000;
    ugpr->rbp = 0x8000;
    ugpr->switch_flag = flag;
    ugpr->rflags = 0x202;
    ugpr->rip = 0x1000;

    do_eswitch(flag);

    return 0;
}
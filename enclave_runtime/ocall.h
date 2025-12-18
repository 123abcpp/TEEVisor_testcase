#ifndef OCALL_H
#define OCALL_H
#include <stdint.h>
#include "../enclave_lib/enclave_runtime.h"
#include "./mm/mm.h"
#include "./utils.h"

int do_eclone(struct ocall_clone *clone);
int do_ocall(uint64_t rdi, uint64_t rsi);
void ocall_print(char* str, int len);
void ocall_emodt(struct sgx_enclave_modify_types* metadata);
void ocall_clone_thread(struct ocall_clone_thread *clone_thread);
void ocall_get_test_case(struct ocall_get_test_case *test_case);
extern void __do_eexit(uint64_t rdi, uint64_t rsi);
void do_eexit(uint64_t rdi, uint64_t rsi);
int do_eaccept(uint64_t addr, uint64_t flags);
int do_emodp(uint64_t addr, uint64_t flags);
int do_ereport(sgx_target_info_t* target_info, sgx_report_data_t* report_data, sgx_report_t* out_put_report);
int do_egetkey(sgx_key_request_t* key_request, uint64_t* output_addr);
int do_emodpe(uint64_t addr, uint64_t flags);
int do_esetussa(uint64_t addr);
int do_eswitch(sgx_switch_flag_t switch_flag);
int do_eraise(uint32_t exitinfo, uint64_t maddr, uint32_t errcd_value);

#ifdef EXCEPTION_LOG
extern uint64_t eswitch_tsc;
#endif
#endif
#include "../enclave_lib/enclave_offsets.h"
#include "../enclave_lib/enclave_runtime.h"
.extern do_eexit handle_timer

.macro HANDLER_DEFAULT_ENTRY name
\name:
    jmp runtime_default_exception_handler_entry
    .zero 128 - (. - \name)
.endm

.macro HANDLER_INTERNAL_ENTRY name
\name:
    jmp runtime_internal_handler_entry
    .zero 128 - (. - \name)
.endm

.section ".text.handler", "ax", @progbits
	.balign	4096
handler_entry:
HANDLER_DEFAULT_ENTRY entry_handler_default
HANDLER_INTERNAL_ENTRY entry_handler_de
HANDLER_DEFAULT_ENTRY entry_handler_db
HANDLER_DEFAULT_ENTRY entry_handler_bp
HANDLER_DEFAULT_ENTRY entry_handler_ud
HANDLER_INTERNAL_ENTRY entry_handler_gp
HANDLER_DEFAULT_ENTRY entry_handler_pf
HANDLER_INTERNAL_ENTRY entry_handler_mf
HANDLER_INTERNAL_ENTRY entry_handler_ac
HANDLER_INTERNAL_ENTRY entry_handler_xf
HANDLER_DEFAULT_ENTRY entry_handler_cp

entry_handler_syscall:
    jmp runtime_syscall_handler_entry
    .zero 128 - (. - entry_handler_syscall)

entry_handler_timer:
    jmp runtime_timer_handler_entry
    .zero 128 - (. - entry_handler_timer)
    .rept 19
1:
    jmp runtime_default_exception_handler_entry
    .zero 128 - (. - 1b)
    .endr

.text
runtime_internal_handler_entry:
runtime_default_exception_handler_entry:
    cld
    # RAX -- CSSA
    movq %gs:ENCLAVE_TLS_EXCEPTION_STACK, %rsp
    movq %rax, %r9
    cmpq $0, %rax
    jne runtime_internal_exception
    movq %gs:ENCLAVE_TLS_UGPR, %rdx
    jmp 1f
runtime_internal_exception:
    movq %gs:ENCLAVE_TLS_GPR, %rdx
1:
    movl GPR_EXITINFO(%rdx), %esi
    movq $EEXIT_TRAP, %rdi
    call do_eexit

runtime_syscall_handler_entry:
#ifdef EXCEPTION_LOG
    /* if (rax != 0) goto normal_path */
    testq   %rax, %rax
    jne     1f

    /* rax == 0: read TSC */
    rdtsc                   /* edx:eax = TSC */

    /* combine to 64-bit value in rax */
    shlq    $32, %rdx
    orq     %rdx, %rax

    /* store TSC to 0x6000 */
    movq    %rax, 0x6000

    /* return to userspace */
    sysretq

1:
#endif

    /* if the value is 111, timer test exit*/
    cmpq $111, %rax
    jne 2f
    movq $111, %rsi /* set rsi to 111 for later print timer count*/

2:
    movq $EEXIT_OCALL_SYSCALL, %rdi
    call do_ocall

runtime_timer_handler_entry:
    mov %rax, %rdi
    call handle_timer


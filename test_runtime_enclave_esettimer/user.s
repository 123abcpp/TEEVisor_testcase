.section .text
.globl _start

_start:
    /* ---- initial TSC ---- */
    rdtsc
    shlq $32, %rdx
    orq  %rdx, %rax
    movq %rax, %r8          /* start TSC */

loop:
    /* ---- read current TSC ---- */
    rdtsc
    shlq $32, %rdx
    orq  %rdx, %rax

    /* delta = current - start */
    subq %r8, %rax

    /* compare with 3,000,000,000 cycles */
    movabs $3000000000, %rcx
    cmpq %rcx, %rax
    jl loop                 /* if < threshold, keep looping */

    /* ---- exit once threshold reached ---- */
    movq $111, %rax         /* customized value*/
    xor  %rdi, %rdi         /* status = 0 */
    syscall

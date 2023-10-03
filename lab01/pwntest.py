import pow as pw
from pwn import *
import base64

def solve_math(r):
    math = r.recvall()
    print(math)
    # num1 = math[2]
    # num2 = math[4]
    # oper = math[3]
    # print(num1)
    # print(num2)
    # print(oper)

r = remote('up23.zoolab.org', 10363)
pw.solve_pow(r)
r.recvlines(3)
math = r.recvuntil(b'?').decode()
ls = math.split(' ')
# print(ls)
times = int(ls[3])
for i in range(times):
    if(i!=0):
        math = r.recvuntil(b'?').decode()
        ls = math.split(' ')
    number = 0
    num1 = int(ls[-5])
    oper = ls[-4]
    num2 = int(ls[-3])
    if oper=="+":
        number = num1+num2
    elif oper=="-":
        number = num1-num2
    elif oper=="*":
        number = num1*num2
    elif oper=="/":
        number = num1/num2
    elif oper=="%":
        number = num1%num2
    elif oper=="**":
        number = num1**num2
    elif oper=="//":
        number = num1//num2

    six = str(hex(number))
    if len(six)%2==1:
        six = six[0:2]+'0'+six[2:]
    # print(six)
    answer= ""
    for i in range(2, len(six),2):
        answer = six[i:i+2] + answer
    # answer  = '0x'+answer
    ans = bytearray.fromhex(answer)
    ans = base64.b64encode(ans)

    r.sendline(ans.decode())
r.interactive()
r.close()

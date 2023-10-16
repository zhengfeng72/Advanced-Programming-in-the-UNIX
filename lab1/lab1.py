

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break;
    print(time.time(), "done.")

    r.sendlineafter(b'string S: ', base64.b64encode(solved))

if __name__ == '__main__':
    #r = remote('localhost', 10330);
    r = remote('up23.zoolab.org', 10363)
    solve_pow(r)

    for i in range(3):
        r.recvline().decode()

    num = int(r.recvline().decode().split(" ")[3])
    print(num)

    for i in range(num):
        
        text = r.recv().decode().split(" ")
        # print(text)
        num1 = int(text[len(text)-6])
        sign = text[len(text)-5]
        num2 = int(text[len(text)-4])
        print(i,num1, sign, num2)
        
        result = 0
        #########################
        ######## check sign #####
        #########################
        if(sign=="+"):
            result = num1 + num2
        elif(sign=="-"):
            result = num1 - num2
        elif(sign=="//"):
            result = num1 / num2
        elif(sign=="*"):
            result = num1 * num2
        elif(sign=="**"):
            result = num1 ** num2
        elif(sign=="%"):
            result = num1 % num2

        print(result)     
        byte_num = math.ceil(math.log(result)/math.log(256))
        byte_ans = int(result).to_bytes(byte_num, 'little')
        ans = base64.b64encode(byte_ans)

        print(ans,'\n')
        r.sendline(ans)
        sleep(0.2)
    r.interactive()
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :


# pop rax
# ret 


from pwn import * 

context.arch = 'amd64'


print(asm("""pop rax
ret"""))

print(asm("""pop rdi
ret"""))

asm("""syscall 
ret""")


import ctypes
libc = ctypes.CDLL('libc.so.6')
libc.srand()

a.x
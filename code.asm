BITS 64

section .data
        ; Align to the nearest 2 byte boundary, must be a power of two
        align 2
        ; String, which is just a collection of bytes, 0xA is newline
      	str:     db 'Je suis trop un hacker',0xa
        strLen:  equ $-str

SECTION .text
global main

main:
        ; save context
        push rax
        push rcx
        push rdx
        push rsi
        push rdi
        push r11

        ; fill here later
        mov rax, 1
        mov rdi, 1
        mov rdx, strLen
        lea rsi, [rel str]
        syscall

        ; load context
	pop r11
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rax

        ; return
;        push 0x4022e0
	ret

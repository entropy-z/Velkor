[BITS 64]

DEFAULT REL
EXTERN Entry

GLOBAL Start

EXTERN LoadLibraryPtr

GLOBAL CallbackLoadLib

GLOBAL StartPtr
GLOBAL RetStartPtr

GLOBAL RetEndPtr
GLOBAL EndPtr

[SECTION .text$A]
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  Entry
        mov   rsp, rsi
        pop   rsi
        ret

    StartPtr:
        call RetStartPtr
        ret

    RetStartPtr:
        mov	rax, [rsp]
        sub rax, 0x1b  
        ret           

[SECTION .text$B]
CallbackLoadLib:
    mov rcx, rdx
    xor rdx, rdx
    call LoadLibraryPtr
    jmp rax

[SECTION .text$E]
    EndPtr:
        call RetEndPtr
        ret

    RetEndPtr:
        mov rax, [rsp]
        add	rax, 0xb  
        ret            

[SECTION .text$P]
    VelkorEndStr:
        DB 'V', 'E', 'L', 'K', 'O', 'R'
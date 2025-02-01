GLOBAL Start
GLOBAL StartPtr
GLOBAL EndPtr

EXTERN Entry

[SECTION .text$A]
    Start
        push rsi
        mov  rsi, rsp
        and  rsp, 0x0FFFFFFFFFFFFFFF0
        sub  rsp, 0x20
        call Entry
        mov  rsp, rsi
        pop  rsi
        ret 

    StartPtr:
        call PtrStart
        ret

    PtrStart:
        mov	rax, [rsp] 
        sub rax, 0x1b  
        ret            


[SECTION .text$C]
    EndPtr:
        call GarouPtrEnd
        ret

    GarouPtrEnd:
        mov rax, [rsp]  
        add	rax, 0xb    
        ret             

[SECTION .text$D]
    SymEnd:
        DB 'C', 'O', 'D', 'E', '-', 'E', 'N', 'D'
[BITS 32]

DEFAULT REL
EXTERN _Entry

GLOBAL Start

GLOBAL StartPtr
GLOBAL RetStartPtr

GLOBAL RetEndPtr
GLOBAL EndPtr

[SECTION .text$A]
    Start:
        push   ebx              
        mov    ebx, esp        
        and    esp, 0xFFFFFFF0  
        sub    esp, 0x10        
        call   _Entry            
        mov    esp, ebx         
        pop    ebx              
        ret

    StartPtr:
        call RetStartPtr
        ret

    RetStartPtr:
        mov	eax, [esp]         
        sub eax, 0x17           
        ret

[SECTION .text$E]
    EndPtr:
        call RetEndPtr
        ret

    RetEndPtr:
        mov eax, [esp]          
        add eax, 0x8            
        ret

[SECTION .text$P]
    VelkorEndStr:
        DB 'V', 'E', 'L', 'K', 'O', 'R'

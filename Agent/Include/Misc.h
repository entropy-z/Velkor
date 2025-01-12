#ifndef MISC_H
#define MISC_H

#include <Velkor.h>

/*=============[ Auxiliars.cc ]=============*/

EXTERN_C VOID volatile ___chkstk_ms(
        VOID
);

PWSTR GetEnv(
    VOID
);

PVOID LdrLoadModule2(
    _In_ PSTR ModuleName
);

PSTR ErrorHandler(
    _In_ UINT32 ErrorCode,
    _In_ PSTR   InputString
);

PVOID FindJmpGadget(
    _In_ PVOID  ModuleBase,
    _In_ UINT16 RegValue
);

PVOID LdrLoadModule(
    _In_ ULONG Hash
);

PVOID LdrLoadFunc( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
);

template < typename T >
ULONG HashString(
    _In_ T      String,
    _In_ SIZE_T Length
);

ULONG Random32(
	void
);

/*=============[ Core.cc ]=============*/

VOID SetNtStatusToSystemError(
    _In_ NTSTATUS NtStatus
);

BOOL VelkorInit(
    PVOID Parameter
);

/*==============[ Hashing ]==============*/

#define H_MAGIC_KEY          5555 // __TIME__[5] + __TIME__[0] + __TIME__[1] + __TIME__[2] + __TIME__[3]
#define H_MAGIC_SEED         5 

#define XprCryptBase    XPR( "Cryptbase.dll" )
#define XprIphlpapi     XPR( "IPHLPAPI.DLL" )
#define XprKernel32     XPR( "KERNEL32.DLL" )
#define XprKernelBase   XPR( "KERNELBASE.dll" )
#define XprMsvcrt       XPR( "msvcrt.dll" )
#define XprNtdll        XPR( "ntdll.dll" )
#define XprWininet      XPR( "wininet.dll" )
#define XprWinhttp      XPR( "winhttp.dll" )
#define XprAdvapi32     XPR( "ADVAPI32.dll" )

#define CONSTEXPR       constexpr

#define XPR( x ) ExpStrA( ( x ) )

CONSTEXPR ULONG ExpStrA(
    _In_ PCHAR String
) {
    ULONG Hash = H_MAGIC_KEY;
    CHAR Char  = 0;

    if ( !String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' && Char <= 'z' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

#endif // MISC_H
#ifndef GENERAL_H
#define GENERAL_H

#include <windows.h>
#include <stdio.h>

#include <Deps.h>

typedef struct {
    PSTR  PipeName;
    PVOID Argument;
    BOOL  Inline;
} POSTEX_ARGS, *PPOSTEX_ARGS;

/* ==============[ Dereference ]============== */

#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

/* ==============[ Casting ]============== */

#define C_PTR( x )  reinterpret_cast<PVOID>( x )
#define B_PTR( x )  reinterpret_cast<PBYTE>( x )
#define UC_PTR( x ) reinterpret_cast<PUCHAR>( x )

#define A_PTR( x )   reinterpret_cast<PCHAR>( x )
#define W_PTR( x )   reinterpret_cast<PWCHAR>( x )

#define U_64( x ) reinterpret_cast<UINT64>( x )
#define U_32( x ) reinterpret_cast<UINT32>( x )
#define U_16( x ) reinterpret_cast<UINT16>( x )
#define U_8( x )  reinterpret_cast<UINT8>( x )

#define W_PTR( x )   ( ( PWCHAR    ) ( x ) )
#define A_PTR( x )   ( ( PCHAR     ) ( x ) )
#define B_PTR( x )   ( ( PBYTE     ) ( x ) )
#define C_PTR( x )   ( ( LPVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR  ) ( x ) )

/* ===========[ Macros ]=========== */

#define D_SEC( x ) 	__attribute__( ( section( ".text$" #x ) ) )
#define D_API( x )  __typeof__( x ) * x

#define H_MAGIC_KEY     5555
#define H_MAGIC_SEED    5 

#define CONSTEXPR       constexpr

#define XprCryptBase    XPR( "Cryptbase.dll" )
#define XprIphlpapi     XPR( "IPHLPAPI.DLL" )
#define XprKernel32     XPR( "KERNEL32.DLL" )
#define XprKernelBase   XPR( "KERNELBASE.dll" )
#define XprMsvcrt       XPR( "msvcrt.dll" )
#define XprNtdll        XPR( "ntdll.dll" )
#define XprWininet      XPR( "wininet.dll" )
#define XprWinhttp      XPR( "winhttp.dll" )
#define XprAdvapi32     XPR( "ADVAPI32.dll" )

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

/* ===========[ Asm ]=========== */

EXTERN_C PVOID StartPtr();
EXTERN_C PVOID EndPtr();

/* ===========[ Win32 ]=========== */

enum {
    eKernel32,
    eKernelBase,
    eMsvcrt,
    eNtdll
} eMODULES;

#define M_LENGTH ( eNtdll + 1 )

typedef struct {
    D_API( VirtualAlloc );
    D_API( printf );
    D_API( CreateNamedPipeA );
    D_API( AllocConsole );
    D_API( ConnectNamedPipe );
} FUNCS, *PFUNCS;

typedef struct {
    PVOID Module[M_LENGTH];
    FUNCS FunctionPtr;
} WIN32_MF, *PWIN32_MF;

#define FuncPtr Win32.FunctionPtr
#define ModPtr  Win32.Module

/* ==============[ Funcs Defines ]============== */

typedef HMODULE (*fnLoadLibraryA)( LPCSTR );

PVOID LdrLoadFunc( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
);

PVOID LdrLoadModule(
    _In_ ULONG Hash
);

ULONG HashString(
    _In_ PCHAR  String,
    _In_ SIZE_T Length
);

/* ==============[ namespaces exports ]============== */

namespace Memory {

    PVOID Copy( PVOID Dest, const PVOID Src, SIZE_T Size );
    VOID  Zero( PVOID Ptr,  SIZE_T Size );
    VOID  Set(  PVOID Dest, UCHAR Value, SIZE_T Size );

}

namespace String {

    SIZE_T WCharToChar( PCHAR Dest, PWCHAR Src, SIZE_T MaxAllowed );
    SIZE_T CharToWChar( PWCHAR Dest, PCHAR Src, SIZE_T MaxAllowed );
    SIZE_T LengthA( LPCSTR String );
    SIZE_T LengthW( LPCWSTR String );
    INT    CompareCountA( PCSTR Str1, PCSTR Str2, INT16 Count );
    INT    CompareA( LPCSTR Str1, LPCSTR Str2 );
    INT    CompareW( LPCWSTR Str1, LPCWSTR Str2 );
    void   ToUpperCaseChar(char* str);
    void   ToLowerCaseChar( PCHAR Str );
    WCHAR  ToLowerCaseWchar( WCHAR Ch );
    PCHAR  CopyA( PCHAR Dest, LPCSTR Src );
    PWCHAR CopyW( PWCHAR Dest, LPCWSTR Src );
    void   ConcatA( PCHAR Dest, LPCSTR Src );
    void   ConcatW( PWCHAR Dest, LPCWSTR Src );
    BOOL   IsStringEqual( LPCWSTR Str1, LPCWSTR Str2 );
    VOID   InitUnicode( PUNICODE_STRING UnicodeString, PWSTR Buffer );
    
}

#endif // GENERAL_H
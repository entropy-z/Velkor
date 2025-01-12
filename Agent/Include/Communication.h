#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <Velkor.h>
#include <Defines.h>

typedef struct {
    UINT32  CommandID;
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    BOOL    Encrypt;
} PACKAGE, *PPACKAGE;

typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;

    BOOL    Endian;
} PARSER, *PPARSER;

BOOL WebTransferInit(
    VOID
);

BOOL WebTransferSend(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
);

VOID PkgAddInt32( 
    _In_ PPACKAGE Package, 
    _In_ UINT32   dataInt 
);

VOID PkgAddInt64( 
    _In_ PPACKAGE Package, 
    _In_ UINT64   dataInt 
);

VOID PkgAddPad( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
);

VOID PkgAddBytes( 
    _In_ PPACKAGE Package, 
    _In_ PUCHAR   Data, 
    _In_ SIZE_T   Size 
);

PPACKAGE PackageCreate( 
    _In_ UINT32 CommandID 
);

PPACKAGE PackageNew( 
    VOID
);

VOID PackageDestroy( 
    _In_ PPACKAGE Package 
);

BOOL PkgTransmit( 
    _In_  PPACKAGE Package, 
    _Out_ PVOID*   Response, 
    _Out_ PUINT64  Size 
);

VOID PkgTransmitError(
    _In_ UINT32 ErrorCode,
    _In_ PSTR   InputString,
    _In_ BOOL   bNtStatus
);

VOID PkgAddBool(
    _Inout_ PPACKAGE Package,
    _In_    BOOLEAN  Data
);

VOID PkgAddString( 
    _In_ PPACKAGE package, 
    _In_ PCHAR    data 
);

VOID PkgAddWString( 
    _In_ PPACKAGE package, 
    _In_ PWCHAR   data 
);

VOID ParserNew( 
    _In_ PPARSER parser, 
    _In_ PVOID   Buffer, 
    _In_ UINT32  size 
);

INT ParserGetInt32( 
    _In_ PPARSER parser 
);

PCHAR ParserGetBytes( 
    _In_ PPARSER parser, 
    _In_ PUINT32 size 
);

VOID ParserDestroy( 
    _In_ PPARSER Parser 
);

PCHAR ParserGetString( 
    _In_ PPARSER parser, 
    _In_ PUINT32 size 
);

INT16 ParserGetInt16( 
    _In_ PPARSER parser
);

INT64 ParserGetInt64( 
    _In_ PPARSER parser 
);

BOOL ParserGetBool( 
    _In_ PPARSER parser 
);

BYTE ParserGetByte( 
    _In_ PPARSER parser 
);

#endif // COMMUNICATION_H
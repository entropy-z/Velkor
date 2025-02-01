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

namespace Web {

    BOOL TransferInit(
        VOID
    );

    BOOL TransferSend(
        _In_      PVOID   Data,
        _In_      UINT64  Size,
        _Out_opt_ PVOID  *RecvData,
        _Out_opt_ UINT64 *RecvSize
    );

}

namespace Package {

    VOID AddInt32( 
        _In_ PPACKAGE Package, 
        _In_ UINT32   dataInt
    );

    VOID AddInt64( 
        _In_ PPACKAGE Package, 
        _In_ UINT64   dataInt 
    );

    VOID AddPad( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    );

    VOID AddBytes( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    );

    PPACKAGE Create( 
        _In_ UINT32 CommandID 
    );

    PPACKAGE New( 
        VOID
    );

    VOID Destroy( 
        _In_ PPACKAGE Package 
    );

    BOOL Transmit( 
        _In_  PPACKAGE Package, 
        _Out_ PVOID*   Response, 
        _Out_ PSIZE_T  Size 
    );

    VOID TransmitError(
        _In_ UINT32 ErrorCode,
        _In_ PSTR   InputString
    );

    VOID AddBool(
        _Inout_ PPACKAGE Package,
        _In_    BOOLEAN  Data
    );

    VOID AddString( 
        _In_ PPACKAGE package, 
        _In_ PCHAR    data 
    );

    VOID AddWString( 
        _In_ PPACKAGE package, 
        _In_ PWCHAR   data 
    );

}

namespace Parser {

    VOID New( 
        _In_ PPARSER parser, 
        _In_ PVOID   Buffer, 
        _In_ UINT32  size 
    );

    INT GetInt32( 
        _In_ PPARSER parser 
    );

    PCHAR GetBytes( 
        _In_ PPARSER parser, 
        _In_ PUINT32 size 
    );

    VOID Destroy ( 
        _In_ PPARSER Parser 
    );

    PCHAR GetString( 
        _In_ PPARSER parser, 
        _In_ PUINT32 size 
    );

    INT16 GetInt16( 
        _In_ PPARSER parser
    );

    INT64 GetInt64( 
        _In_ PPARSER parser 
    );

    BOOL GetBool( 
        _In_ PPARSER parser 
    );

    BYTE GetByte( 
        _In_ PPARSER parser 
    );

}

#endif // COMMUNICATION_H
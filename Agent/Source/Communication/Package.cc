#include <Velkor.h>

D_SEC( B ) VOID Int64ToBuffer( 
    _In_ PUCHAR Buffer, 
    _In_ UINT64 Value 
) {
    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

D_SEC( B ) VOID Int32ToBuffer( 
    _In_ PUCHAR Buffer, 
    _In_ UINT32 Size 
) {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

namespace Package {

    D_SEC( B ) VOID AddInt32( 
        _In_ PPACKAGE Package, 
        _In_ UINT32   dataInt 
    ) {
        Package->Buffer = VkMem::Heap::ReAlloc( Package->Buffer, Package->Length + sizeof( UINT32 ) );

        Int32ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

        Package->Size   =   Package->Length;
        Package->Length +=  sizeof( UINT32 );
    }

    D_SEC( B ) VOID AddInt64( 
        _In_ PPACKAGE Package, 
        _In_ UINT64   dataInt 
    ) {
        Package->Buffer = VkMem::Heap::ReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT64 )
        );

        Int64ToBuffer( UC_PTR( Package->Buffer ) + Package->Length, dataInt );

        Package->Size   =  Package->Length;
        Package->Length += sizeof( UINT64 );
    }

    D_SEC( B ) VOID AddPad( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) {
        Package->Buffer = VkMem::Heap::ReAlloc(
            Package->Buffer,
            Package->Length + Size
        );

        VkMem::Copy( C_PTR( U_64( Package->Buffer ) + ( Package->Length ) ), C_PTR( Data ), Size );

        Package->Size   =  Package->Length;
        Package->Length += Size;
    }

    D_SEC( B ) VOID AddBytes( 
        _In_ PPACKAGE Package, 
        _In_ PUCHAR   Data, 
        _In_ SIZE_T   Size 
    ) {
        AddInt32( Package, Size );

        Package->Buffer = VkMem::Heap::ReAlloc( Package->Buffer, Package->Length + Size );

        Int32ToBuffer( UC_PTR( U_64( Package->Buffer ) + ( Package->Length - sizeof( UINT32 ) ) ), Size );

        VkMem::Copy( C_PTR( U_64( Package->Buffer ) + Package->Length ), C_PTR( Data ), Size );

        Package->Size   =   Package->Length;
        Package->Length +=  Size;
    }

    D_SEC( B ) PPACKAGE Create( 
        _In_ UINT32 CommandID 
    ) {
        VELKOR_INSTANCE

        PPACKAGE Package = NULL;

        Package            = (PPACKAGE)( VkMem::Heap::Alloc( sizeof( PACKAGE ) ) );
        Package->Buffer    = VkMem::Heap::Alloc( sizeof( BYTE ) );
        Package->Length    = 0;
        Package->CommandID = CommandID;
        Package->Encrypt   = FALSE;

        AddInt32( Package, 0 );
        AddInt32( Package, VELKOR_MAGIC_VALUE );
        AddInt32( Package, Velkor->Session.AgentId );
        AddInt32( Package, CommandID );

        return Package;
    }

    // For serialize raw data
    D_SEC( B ) PPACKAGE New( 
        VOID
    ) {
        PPACKAGE Package = NULL;

        Package          = (PPACKAGE)( VkMem::Heap::Alloc( sizeof( PACKAGE ) ) );
        Package->Buffer  = VkMem::Heap::Alloc( 0 );
        Package->Length  = 0;
        Package->Encrypt = TRUE;

        AddInt32( Package, 0 );
        AddInt32( Package, 0 );

        return Package;
    }

    D_SEC( B ) VOID Destroy( 
        _In_ PPACKAGE Package 
    ) {
        VELKOR_INSTANCE

        if ( ! Package ) {
            return;
        }
        if ( ! Package->Buffer ) {
            return;
        }

        VkMem::Heap::Free( Package->Buffer, Package->Length );
        VkMem::Heap::Free( Package, sizeof( PACKAGE ) );
        
        return;
    }

    D_SEC( B ) BOOL Transmit( 
        _In_  PPACKAGE Package, 
        _Out_ PVOID*   Response, 
        _Out_ PSIZE_T  Size 
    ) {
        BOOL Success     = FALSE;

        if ( Package ) {
            Int32ToBuffer( UC_PTR( Package->Buffer ), Package->Length - sizeof( UINT32 ) );

            if ( Web::TransferSend( Package->Buffer, Package->Length, Response, Size ) ) {
                Success = TRUE;
            }

            Package::Destroy( Package );
        }
        else
            Success = FALSE;

        return Success;
    }

    D_SEC( B ) VOID TransmitError(
        _In_ UINT32 ErrorCode,
        _In_ PSTR   InputString
    ) {
        VELKOR_INSTANCE

        if ( VELKOR_PACKAGE ) Package::Destroy( VELKOR_PACKAGE );

        BOOL bNtStatus = FALSE;

        if ( Velkor->Session.SyscallMethod != VkCallWinApi ) bNtStatus = TRUE;

        if ( bNtStatus ) ErrorCode = VkCall<UINT32>( XprNtdll, XPR( "RtlNtStatusToDosError" ), ErrorCode );

        // U37_PACKAGE = Package::Create( Stage37Error );
        
        PSTR ErrorMessage = ErrorHandler( ErrorCode, InputString );

        // AddInt32(  U37_PACKAGE, ErrorCode );
        // AddString( U37_PACKAGE, ErrorMessage );
        // Transmit(  U37_PACKAGE, NULL, NULL );
    }

    D_SEC( B ) VOID AddBool(
        _Inout_ PPACKAGE Package,
        _In_    BOOLEAN  Data
    ) {    
        if ( ! Package ) return;

        Package->Buffer = VkMem::Heap::ReAlloc( 
            Package->Buffer, 
            Package->Length + sizeof( UINT32 )
        );

        Int32ToBuffer( UC_PTR( U_64( Package->Buffer ) + Package->Length ), Data ? 1 : 0 );

        Package->Length += sizeof( UINT32 );
    }

    D_SEC( B ) VOID AddString( 
        _In_ PPACKAGE package, 
        _In_ PCHAR    data 
    ) {
        AddBytes( package, (PBYTE) data, VkStr::LengthA( data ) );
    }

    D_SEC( B ) VOID AddWString( 
        _In_ PPACKAGE package, 
        _In_ PWCHAR   data 
    ) {
        AddBytes( package, (PBYTE) data, VkStr::LengthW( data ) * 2 );
    }

}

namespace Parser {

    D_SEC( B ) void New( 
        _In_ PPARSER parser, 
        _In_ PVOID   Buffer, 
        _In_ UINT32  size 
    ) {
        if ( parser == NULL )
            return;

        parser->Original = A_PTR( VkMem::Heap::Alloc( size ) );
        VkMem::Copy( C_PTR( parser->Original ), C_PTR( Buffer ), size );
        parser->Buffer   = parser->Original;
        parser->Length   = size;
        parser->Size     = size;
    }

    D_SEC( B ) INT GetInt32( 
        _In_ PPARSER parser 
    ) {
        INT32 intBytes = 0;

        if ( parser->Length < 4 )
            return 0;

        VkMem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 4 );

        parser->Buffer += 4;
        parser->Length -= 4;

        if ( ! parser->Endian )
            return ( INT ) intBytes;
        else
            return ( INT ) __builtin_bswap32( intBytes );
    }

    D_SEC( B ) PCHAR GetBytes( 
        _In_ PPARSER parser, 
        _In_ PUINT32 size 
    ) {
        UINT32  Length  = 0;
        PCHAR   outdata = NULL;

        if ( parser->Length < 4 )
            return NULL;

        VkMem::Copy( C_PTR( &Length ), C_PTR( parser->Buffer ), 4 );
        parser->Buffer += 4;

        if ( parser->Endian )
            Length = __builtin_bswap32( Length );

        outdata = parser->Buffer;
        if ( outdata == NULL )
            return NULL;

        parser->Length -= 4;
        parser->Length -= Length;
        parser->Buffer += Length;

        if ( size != NULL )
            *size = Length;

        return outdata;
    }

    D_SEC( B ) VOID Destroy( 
        _In_ PPARSER Parser 
    ) {
        if ( Parser->Original ) {
            VkMem::Heap::Free( Parser->Original, Parser->Length );
        }
    }

    D_SEC( B ) PCHAR GetString( 
        _In_ PPARSER parser, 
        _In_ PUINT32 size 
    ) {
        return ( PCHAR ) Parser::GetBytes( parser, size );
    }

    D_SEC( B ) PWCHAR GetWString( 
        _In_ PPARSER parser, 
        _In_ PUINT32 size 
    ) {
        return ( PWCHAR ) Parser::GetBytes( parser, size );
    }

    D_SEC( B ) INT16 GetInt16( 
        _In_ PPARSER parser
    ) {
        INT16 intBytes = 0;

        if ( parser->Length < 2 )
            return 0;

        VkMem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 2 );

        parser->Buffer += 2;
        parser->Length -= 2;

        return intBytes;
    }

    D_SEC( B ) INT64 GetInt64( 
        _In_ PPARSER parser 
    ) {
        INT64 intBytes = 0;

        if ( ! parser )
            return 0;

        if ( parser->Length < 8 )
            return 0;

        VkMem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 8 );

        parser->Buffer += 8;
        parser->Length -= 8;

        if ( !parser->Endian )
            return ( INT64 ) intBytes;
        else
            return ( INT64 ) __builtin_bswap64( intBytes );
    }

    D_SEC( B ) BOOL GetBool( 
        _In_ PPARSER parser 
    ) {
        INT32 intBytes = 0;

        if ( ! parser )
            return 0;

        if ( parser->Length < 4 )
            return 0;

        VkMem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 4 );

        parser->Buffer += 4;
        parser->Length -= 4;

        if ( !parser->Endian )
            return intBytes != 0;
        else
            return __builtin_bswap32( intBytes ) != 0;
    }

    D_SEC( B ) BYTE GetByte( 
        _In_ PPARSER parser 
    ) {
        BYTE intBytes = 0;

        if ( parser->Length < 1 )
            return 0;

        VkMem::Copy( C_PTR( &intBytes ), C_PTR( parser->Buffer ), 1 );

        parser->Buffer += 1;
        parser->Length -= 1;

        return intBytes;
    }

}

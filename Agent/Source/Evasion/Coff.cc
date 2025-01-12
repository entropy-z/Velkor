#include <Velkor.h>

typedef struct {
    union {
        PBYTE               Buffer;
        PIMAGE_FILE_HEADER  FileHeader;
    };

    ULONG                   Size;
    PIMAGE_RELOCATION       Relocation;
    PIMAGE_SYMBOL           Symbols;
    PIMAGE_SECTION_HEADER   Sections;
} COFF_DATA, *PCOFF_DATA;

D_SEC( B ) BOOL CoffLoader( 
    _In_ PSTR  EntryPoint,
    _In_ PVOID CoffPtr,
    _In_ PBYTE Argv,
    _In_ ULONG Argc
) {
    VELKOR_INSTANCE

    COFF_DATA CoffData   = { 0 };
    PVOID     CoffBase   = NULL;
    PSTR      SymbolName = NULL;    

    CoffData.Buffer   = B_PTR( CoffPtr );
    CoffData.Symbols  = (PIMAGE_SYMBOL)( CoffData.Buffer + CoffData.FileHeader->PointerToSymbolTable );
    CoffData.Sections = (PIMAGE_SECTION_HEADER)( CoffData.Buffer + sizeof( IMAGE_FILE_HEADER ) );

    for ( INT x = 0; x < CoffData.FileHeader->NumberOfSections; x++ ) {
        CoffData.Size       += PAGE_ALIGN( CoffData.Sections[x].SizeOfRawData );
        CoffData.Relocation  = (PIMAGE_RELOCATION)( CoffData.Buffer + CoffData.Sections[x].PointerToRelocations );

        for( INT y = 0; y < CoffData.Sections[x].NumberOfRelocations; y++ ) {
            CoffData.Symbols[CoffData.Relocation->SymbolTableIndex];
            if   ( CoffData.Symbols->N.Name.Short ) SymbolName = A_PTR( CoffData.Symbols->N.ShortName );
            else SymbolName = A_PTR( ( CoffData.Symbols + CoffData.FileHeader->NumberOfSymbols ) + CoffData.Symbols->N.Name.Short );
        }

        if ( FuncPtr.strncmp( "__imp_", SymbolName, 6 ) == 0 ) CoffData.Size += sizeof( PVOID );

        CoffData.Relocation = CoffData.Relocation + sizeof( IMAGE_RELOCATION );
    }

    PAGE_ALIGN( CoffData.Size );
    
    CoffBase = VkMem::Alloc( NULL, CoffData.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !CoffBase ) return FALSE;

    
}
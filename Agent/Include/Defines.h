#ifndef MACROS_H
#define MACROS_H

#include <windows.h>

#include <Misc.h>
#include <Evasion.h>

typedef enum {
    eNtOpenProcess,
    eNtOpenThread,
    eNtTerminateProcess,
    eNtTerminateThread,
    eNtCreateThreadEx,
    eNtResumeThread,
    eNtOpenProcessToken,
    eNtOpenThreadToken,
    eNtWriteVirtualMemory,
    eNtProtectVirtualMemory,
    eNtQueryVirtualMemory,
    eNtFreeVirtualMemory,
    eNtAllocateVirtualMemory
} eINDIRECT;

typedef enum {
    eMsvcrt,
    eCryptbase,
    eWs2_32,
    eAdvapi32,
    eNetapi32,
    eIphlpapi,
    eWininet,
    eWinHttp,
    eKernelBase,
    eKernel32,
    eNtdll    
} eMODULE;

#define SYS_ENUM_SIZE ( eNtAllocateVirtualMemory + 1 )
#define M_ENUM_SIZE   ( eNtdll + 1 )
#define COFF_LEN      17

EXTERN_C typedef enum {
    VkCallWinApi,
    VkCallNtApi,
    VkCallIndirect
} eSYSCALL;

/*==============[ Dereference ]==============*/

#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

/*==============[ Casting ]==============*/

#define C_PTR( x )  reinterpret_cast<PVOID>( x )
#define B_PTR( x )  reinterpret_cast<PBYTE>( x )
#define UC_PTR( x ) reinterpret_cast<PUCHAR>( x )

#define A_PTR( x )   reinterpret_cast<PCHAR>( x )
#define W_PTR( x )   reinterpret_cast<PWCHAR>( x )

#define U_64( x ) reinterpret_cast<UINT64>( x )
#define U_32( x ) reinterpret_cast<UINT32>( x )
#define U_16( x ) reinterpret_cast<UINT16>( x )
#define U_8( x )  reinterpret_cast<UINT8>( x )

/*==============[ Funcs Defines ]==============*/

typedef HMODULE (*fnLoadLibraryA)( LPCSTR );

EXTERN_C PVOID vRtlCopyMemory( PVOID __restrict__ _Dst, const PVOID __restrict__ _Src, SIZE_T Size );

/*==============[ Expands ]==============*/

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) { sizeof(OBJECT_ATTRIBUTES), n, NULL, a, NULL, NULL }

#define NtCurrentProcessToken()         ( (HANDLE)(-4) )
#define NtCurrentThreadToken()          ( (HANDLE)(-5) )
#define NtCurrentThreadEffectiveToken() ( (HANDLE)(-6) )

EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

EXTERN_C PVOID StartPtr();
EXTERN_C PVOID EndPtr();

#define InstanceOffset()  ( U_64( &__Instance_offset ) )
#define InstancePtr()     ( ( PVELKOR ) C_DEF( C_PTR( U_64( StartPtr() ) ) + InstanceOffset() ) ) 
#define Velkor            ( ( PVELKOR ) __LocalInstance )

#define VELKOR_INSTANCE   PVELKOR __LocalInstance = InstancePtr();

#define SYSCALL_METHOD    Velkor->Session.SyscallMethod
#define VELKOR_PACKAGE    Velkor->CommunicConfig.PackagePtr

#define VelkorMem         Velkor->VelkorMemory
#define TaskMgmt          Velkor->TaskManager
#define SleepConf         Velkor->SleepConfig
#define FuncPtr           Velkor->VkWin32.FunctionPtr
#define CoffCtx           Velkor->PostEx.zCoffCtx
#define PsCtx             Velkor->PostEx.ProcessCtx
#define InjCtx            Velkor->PostEx.InjectionCtx
#define WebConf           Velkor->CommunicConfig.WebConfig
#define VkSys             Velkor->VkWin32.VkSyscall

#define VELKOR_MAGIC_VALUE  0x71717171
#define RBX_REG             0x23
#define PAGE_SIZE           0x1000 
#define STATIC              static
#define INLINE              inline
#define FORCE_INLINE        __forceinline
#define NO_INLINE           __attribute__( ( noinline ) )

#define D_API( x )      __typeof__( x ) * x
#define D_SEC( x )      __attribute__( ( section( ".text$" #x "" ) ) )

#define ST_GLOBAL       __attribute__( ( section( ".global" ) ) )
#define ST_READONLY     __attribute__( ( section( ".rdata" ) ) )

#define PAGE_ALIGN( x ) ( ( (ULONG_PTR) x ) + ( ( PAGE_SIZE - ( ( (ULONG_PTR)x ) & ( PAGE_SIZE - 1 ) ) ) % PAGE_SIZE ) )

/*==============[ Namespace Velkor Macros ]==============*/

#define VkMem     Ground::Memory
#define VkStr     Ground::String
#define VkProcess Ground::Process
#define VkThread  Ground::Thread
#define VkToken   Ground::Token
#define VkFile    Ground::File
#define VkCall    Ground::Api::Call

/*==============[ Debug ]==============*/

#ifdef DEBUG
    #define VkShow( x, ... ) Velkor->VkWin32.FunctionPtr.printf( x, ##__VA_ARGS__ )
#else
    #define VkShow( x, ... ) 
#endif

/*==============[ Velkor Condits ]==============*/

#ifdef _M_IX86
#define CALLING_CONV __stdcall 
#define UINT64  UINT32
#define PUINT64 PUINT32
#else
#define CALLING_CONV __fastcall
#endif

#ifndef VK_SYSCALL_METHOD 
#define VK_SYSCALL_METHOD 0
#endif  

#ifndef VK_SLEEP_MASK
#define VK_SLEEP_MASK 0
#endif

#ifndef VK_SPAWNTO
#define VK_SPAWNTO ""
#endif

#ifndef VK_PS_TYPE
#define VK_PS_TYPE 0
#endif

#ifndef VK_SLEEP_TIME
#define VK_SLEEP_TIME 5
#endif

#ifndef VK_SC_INJ_T
#define VK_SC_INJ_T 0
#endif

#ifndef VK_PE_INJ_T
#define VK_PE_INJ_T 0
#endif

#ifndef VK_COFF_INJ_T
#define VK_COFF_INJ_T 0
#endif

#ifndef HOST_CONFIG
#define HOST_CONFIG  L"127.0.0.1"
#endif

#ifndef PORT_CONFIG
#define PORT_CONFIG 80
#endif

#ifndef USER_AGENT_CONFIG
#define USER_AGENT_CONFIG L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
#endif

#ifndef ADD_HEADERS_CONFIG
#define ADD_HEADERS_CONFIG L""
#endif

#endif // MACROS_H
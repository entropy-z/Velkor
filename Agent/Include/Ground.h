#ifndef GROUND_H
#define GROUND_H

#include <Velkor.h>
#include <Defines.h>
#include <Native.h>

#define M_CACHE_SIZE 12
#define F_CACHE_SIZE 80

typedef enum {
    VelkorTokenProcess,
    VelkorTokenThread
} eOPEN_TOKEN_TYPE;

typedef struct _MODULE_CACHE {
    ULONG   ModuleHash;
    HMODULE Module;
} MODULE_CACHE, *PMODULE_CACHE;

typedef struct _FUNCTION_CACHE {
    ULONG   ModuleHash;
    ULONG   FunctionHash;
    FARPROC Function;
} FUNCTION_CACHE, *PFUNCTION_CACHE;

namespace Ground {

    namespace Api {

        FARPROC GetCachedFunction( ULONG ModuleHash, ULONG FunctionHash );
        HMODULE GetCachedModule( ULONG ModuleHash );
        BOOL    CacheModule( ULONG ModuleHash, HMODULE Module );
        BOOL    CacheFunction( ULONG ModuleHash, ULONG FunctionHash, FARPROC Function );

        template< typename Ret, typename... Args >
        class CallWrapper {
        public:
            D_SEC( C ) STATIC __forceinline Ret Call( ULONG ModuleHash, ULONG FunctionHash, Args... args ) {
                
                HMODULE Module = GetCachedModule( ModuleHash );
                if ( !Module ) {
                    Module = (HMODULE)LdrLoadModule( ModuleHash );
                    if ( !Module ) {
                            //VkShow( "{ERR} Failed to get module base\n" ); return Ret();
                    }
                    CacheModule( ModuleHash, Module );
                }
                FARPROC Function = GetCachedFunction( ModuleHash, FunctionHash );
                if ( !Function ) {
                    Function = (FARPROC)LdrLoadFunc( Module, FunctionHash );
                    if ( !Function ) {
                        //VkShow( "{ERR} Failed to get function base\n" ); return Ret();
                    }
                    CacheFunction( ModuleHash, FunctionHash, Function );
                }
                auto Func = reinterpret_cast< Ret( CALLING_CONV *)( Args... ) >( Function );
                return Func( args... );
            }
        };

        template< typename Ret, typename... Args >
        D_SEC( C ) __forceinline Ret Call( ULONG ModuleHash, ULONG FunctionHash, Args... args ) {
            return CallWrapper< Ret, Args... >::Call( ModuleHash, FunctionHash, args... );
        }
    }

    namespace Process {

        HANDLE Open( UINT32 AccessRights, BOOL bInheritHandle, UINT32 ProcessId );
        BOOL   Kill( HANDLE ProcessHandle, UINT32 ExitCode );
        BOOL   Create( PSTR Path, BOOL bInheritHandle, UINT32 Flags, PSTR CurrentDir, PROCESS_INFORMATION ProcessInf, UINT32 ParentProcId, BOOL BlockDlls ); 
    }

    namespace Thread{

        HANDLE Create( SIZE_T StackSize, PVOID StartAddress, PVOID Parameter, ULONG Flags, PULONG ThreadIdPtr, HANDLE ProcessHandle = NtCurrentProcess() );
        HANDLE Open( ULONG AccessRights, BOOL bInheritHandle, ULONG ThreadId );
        ULONG  Enum( VOID );
    }

    namespace Token {

        BOOL GetUser( PSTR *UserNamePtr, ULONG *UserNameLen, HANDLE TokenHandle = NtCurrentProcessToken() );
    }

    namespace Memory {

        PVOID Copy( PVOID Dest, const PVOID Src, SIZE_T Size );
        VOID  Zero( PVOID Ptr, SIZE_T Size );
        VOID  Set( PVOID Dest, UCHAR Value, SIZE_T Size );

        PVOID  Alloc( PVOID BaseAddress, SIZE_T AllocSize, ULONG AllocType, ULONG AllocProtection, HANDLE ProcessHandle = NtCurrentProcess() );
        BOOL   Write( PVOID BaseAddress, PBYTE Buffer, SIZE_T BuffSize, PSIZE_T BytesWritten, HANDLE ProcessHandle = NtCurrentProcess() );
        BOOL   Protect( PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection, HANDLE ProcessHandle = NtCurrentProcess() );
        SIZE_T Query( PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MbiPtr, HANDLE ProcessHandle = NtCurrentProcess() );
        BOOL   Free( PVOID BaseAddress, SIZE_T SizeToFree, HANDLE ProcessHandle = NtCurrentProcess() );

        namespace Heap {
            
            VOID HeapCrypt( PBYTE Key, ULONG KeySize );

            BOOL QueryCacheHeap( PVOID Ptr, SIZE_T Size = 0 );
            BOOL AddCacheHeap( PVOID Ptr, SIZE_T Size );

            PVOID Alloc( SIZE_T Size );
            PVOID ReAlloc( PVOID Ptr, SIZE_T Size );
            BOOL  Free( PVOID Ptr, SIZE_T Size );
        }
    }

    namespace String {
        SIZE_T WCharToChar( PCHAR Dest, PWCHAR Src, SIZE_T MaxAllowed );
        SIZE_T CharToWChar( PWCHAR Dest, PCHAR Src, SIZE_T MaxAllowed );
        SIZE_T LengthA( LPCSTR String );
        SIZE_T LengthW( LPCWSTR String );
        INT    CompareA( LPCSTR Str1, LPCSTR Str2 );
        INT    CompareW( LPCWSTR Str1, LPCWSTR Str2 );
        void   ToUpperCaseChar(char* str);
        void   ToLowerCaseChar( PCHAR Str );
        WCHAR  ToLowerCaseWchar( WCHAR Ch );
        PCHAR  CopyA( PCHAR Dest, LPCSTR Src );
        PWCHAR CopyW( PWCHAR Dest, LPCWSTR Src );
        void   ConcatA( PCHAR Dest, LPCSTR Src );
        void   ConcatW( PWCHAR Dest, LPCWSTR Src );
        BOOL   IsStringEqual( LPCWSTR Str1, LPCWSTR Str2 );
        VOID   InitUnicode( PUNICODE_STRING UnicodeString, PWSTR Buffer );
    }

    namespace File {

        BOOL Read( PSTR FilePath, PBYTE *FileBuffer, PULONG FileSize );

    }
}

#endif // GROUND_H
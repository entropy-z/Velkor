#include <Velkor.h>

namespace Spoof {

    D_SEC( B ) BOOL CalcStackSize( PVOID ImageBase, PRUNTIME_FUNCTION RuntimeFunc ) {
        ULONG        NtStatus  = STATUS_SUCCESS;
        ULONG        UnwOps    = 0;
        ULONG        OpsInfo   = 0;
        ULONG        Idx       = 0;
        ULONG        CodeCount = 0;
        ULONG        Frmoffset = 0;
        PUNWIND_INFO UnwInfo   = { 0 };
        
        if ( !RuntimeFunc || ImageBase ) return FALSE;

        UnwInfo     = (PUNWIND_INFO)( ImageBase + RuntimeFunc->UnwindData );
        CodeCount   = UnwInfo->CountOfCodes;

        while ( Idx < CodeCount ) {
            UnwOps  = UnwInfo->UnwindCode[Idx].UnwindOp;
            OpsInfo = UnwInfo->UnwindCode[Idx].OpInfo;

            switch ( UnwOps ) {
            case UWOP_SAVE_NONVOL:
                Idx += 1; break;
            case UWOP_PUSH_NONVOL:
                break;
            }
        }

    }

    D_SEC( B ) BOOL ListGadget(
        _In_ PVOID TextPtr,
        _In_ ULONG TextSize,
        _In_ PVOID GadgetPtr
    ) {

    }

}

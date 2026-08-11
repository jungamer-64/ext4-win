#include <ntifs.h>

PDRIVER_CANCEL ext4win_set_cancel_routine(PIRP irp, PDRIVER_CANCEL routine)
{
    return IoSetCancelRoutine(irp, routine);
}

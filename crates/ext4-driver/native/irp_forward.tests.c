/* Lower dispatch may replace its Control flags and parameters. Pending
 * completion must still observe the upper driver's independent pending bit. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _Must_inspect_result_
#define _In_
#define _Inout_
#define NTAPI
#define SL_PENDING_RETURNED 1
#define STATUS_SUCCESS 0
#define STATUS_PENDING 0x103
#define STATUS_FAILURE (-1)
typedef int NTSTATUS;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct {
    unsigned Control;
    unsigned MinorFunction;
    unsigned Parameter;
} IO_STACK_LOCATION;
typedef struct {
    IO_STACK_LOCATION Stack[3];
    unsigned Current;
} IRP, *PIRP;

static DEVICE_OBJECT lower;
static NTSTATUS lower_status;
static unsigned calls;

static void IoSkipCurrentIrpStackLocation(PIRP irp)
{
    irp->Current++;
}

static void IoCopyCurrentIrpStackLocationToNext(PIRP irp)
{
    irp->Stack[irp->Current - 1] = irp->Stack[irp->Current];
    irp->Stack[irp->Current - 1].Control = 0;
}

static NTSTATUS IoCallDriver(PDEVICE_OBJECT device, PIRP irp)
{
    IO_STACK_LOCATION *stack;
    assert(device == &lower);
    irp->Current--;
    stack = &irp->Stack[irp->Current];
    assert(stack->MinorFunction == 1 && stack->Parameter == 73);
    assert(stack->Control == 0);
    stack->Control = 0xE0;
    stack->Parameter = 99;
    calls++;
    return lower_status;
}

#include "irp_forward.h"

int main(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 3; scenario++) {
        IRP pending, immediate;
        pending.Current = immediate.Current = 1;
        pending.Stack[1].Control = SL_PENDING_RETURNED;
        immediate.Stack[1].Control = 0;
        pending.Stack[1].MinorFunction = immediate.Stack[1].MinorFunction = 1;
        pending.Stack[1].Parameter = immediate.Stack[1].Parameter = 73;
        lower_status = scenario == 0 ? STATUS_SUCCESS :
            (scenario == 1 ? STATUS_PENDING : STATUS_FAILURE);
        calls = 0;
        assert(ext4win_forward_pending_irp(&lower, &pending) == lower_status);
        assert(pending.Current == 0);
        assert(pending.Stack[1].Control == SL_PENDING_RETURNED);
        assert(pending.Stack[1].Parameter == 73);
        assert(ext4win_forward_original_irp(&lower, &immediate) == lower_status);
        assert(immediate.Current == 1 && immediate.Stack[1].Parameter == 99);
        assert(calls == 2);
    }
    return 0;
}

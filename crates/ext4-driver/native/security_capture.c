#include <ntifs.h>

#define EXT4WIN_SECURITY_POOL_TAG ((ULONG)0x53773445UL)

#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS                                      \
    (FsRtlIsNtstatusExpected((NTSTATUS)GetExceptionCode())                     \
         ? EXCEPTION_EXECUTE_HANDLER                                           \
         : EXCEPTION_CONTINUE_SEARCH)

/* Requestor output mappings and Type3 input are probed in their original context.
 * I/O Manager input snapshots have a separate native ownership contract. */
#include "io_manager_input.h"
#include "input_validation.h"
#include "cluster_control_capture.h"
#include "requestor_buffer.h"

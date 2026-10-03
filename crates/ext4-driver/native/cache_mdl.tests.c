/* Execute the production MDL protocol against a Cache Manager ownership oracle.
 * This checks chain transfer and range/status behavior; kernel Cc/MM remains a live-test contract. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _Must_inspect_result_
#define NULL ((void *)0)
#define EXT4WIN_CATCH_EXPECTED_EXCEPTIONS 1
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER (-1)
#define STATUS_END_OF_FILE (-2)
#define STATUS_UNSUCCESSFUL (-3)
#define NT_SUCCESS(status) ((status) >= 0)

typedef int NTSTATUS;
typedef unsigned ULONG;
typedef unsigned long long ULONG_PTR;
typedef long long LONGLONG;
typedef struct { LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct { unsigned identity; } MDL, *PMDL;
typedef struct { unsigned identity; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { PMDL MdlAddress; } IRP, *PIRP;
typedef struct { NTSTATUS Status; ULONG_PTR Information; } IO_STATUS_BLOCK;

static MDL pages = { 7 };
static unsigned reads, prepares, read_releases, write_releases, write_aborts;
static ULONG requested;
static LONGLONG position;
static NTSTATUS acquisition_status;
static unsigned acquisition_raises, completion_raises;

#define GetExceptionCode() ((NTSTATUS)__exception_code())
__declspec(dllimport) void __stdcall RaiseException(ULONG, ULONG, ULONG, const ULONG_PTR *);

static void acquire(PFILE_OBJECT file, LARGE_INTEGER *offset, ULONG length, PMDL *chain, IO_STATUS_BLOCK *status)
{
    assert(file->identity == 11 && *chain == NULL);
    requested = length;
    position = offset->QuadPart;
    *chain = &pages;
    status->Status = acquisition_status;
    status->Information = length;
    if (acquisition_raises) { RaiseException((ULONG)STATUS_UNSUCCESSFUL, 0, 0, NULL); }
}
static void CcMdlRead(PFILE_OBJECT file, LARGE_INTEGER *offset, ULONG length, PMDL *chain, IO_STATUS_BLOCK *status)
{
    reads++;
    acquire(file, offset, length, chain, status);
}
static void CcPrepareMdlWrite(PFILE_OBJECT file, LARGE_INTEGER *offset, ULONG length, PMDL *chain, IO_STATUS_BLOCK *status)
{
    prepares++;
    acquire(file, offset, length, chain, status);
}
static void CcMdlReadComplete(PFILE_OBJECT file, PMDL chain)
{
    assert(file->identity == 11 && chain == &pages);
    read_releases++;
}
static void CcMdlWriteComplete(PFILE_OBJECT file, LARGE_INTEGER *offset, PMDL chain)
{
    assert(file->identity == 11 && chain == &pages && offset->QuadPart == position);
    write_releases++;
    if (completion_raises) { RaiseException((ULONG)STATUS_UNSUCCESSFUL, 0, 0, NULL); }
}
static void CcMdlWriteAbort(PFILE_OBJECT file, PMDL chain)
{
    assert(file->identity == 11 && chain == &pages);
    write_aborts++;
}

#include "cache_mdl.h"

int main(void)
{
    FILE_OBJECT file;
    IRP irp;
    LARGE_INTEGER offset;
    ULONG_PTR information = 99;
    file.identity = 11;
    irp.MdlAddress = NULL;
    offset.QuadPart = 80;
    acquisition_status = STATUS_SUCCESS;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 0, offset, 40, 100, &information) == STATUS_SUCCESS);
    assert(reads == 1 && requested == 20 && information == 20 && irp.MdlAddress == &pages);
    assert(ext4win_cache_mdl_transfer(&file, &irp, 1, offset, 0, 0, &information) == STATUS_SUCCESS);
    assert(read_releases == 1 && irp.MdlAddress == NULL && information == 0);
    assert(ext4win_cache_mdl_transfer(&file, &irp, 1, offset, 0, 0, &information) == STATUS_INVALID_PARAMETER);
    assert(read_releases == 1);

    assert(ext4win_cache_mdl_transfer(&file, &irp, 2, offset, 20, 100, &information) == STATUS_SUCCESS);
    assert(prepares == 1 && information == 20 && irp.MdlAddress == &pages);
    assert(ext4win_cache_mdl_transfer(&file, &irp, 3, offset, 0, 0, &information) == STATUS_SUCCESS);
    assert(write_releases == 1 && irp.MdlAddress == NULL);

    acquisition_status = STATUS_UNSUCCESSFUL;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 0, offset, 10, 100, &information) == STATUS_UNSUCCESSFUL);
    assert(read_releases == 2 && irp.MdlAddress == NULL && information == 0);
    assert(ext4win_cache_mdl_transfer(&file, &irp, 2, offset, 10, 100, &information) == STATUS_UNSUCCESSFUL);
    assert(write_aborts == 1 && write_releases == 1 && irp.MdlAddress == NULL && information == 0);

    acquisition_raises = 1;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 0, offset, 10, 100, &information) == STATUS_UNSUCCESSFUL);
    assert(read_releases == 3 && irp.MdlAddress == NULL && information == 0);
    assert(ext4win_cache_mdl_transfer(&file, &irp, 2, offset, 10, 100, &information) == STATUS_UNSUCCESSFUL);
    assert(write_aborts == 2 && irp.MdlAddress == NULL && information == 0);
    acquisition_raises = 0;
    acquisition_status = STATUS_SUCCESS;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 2, offset, 10, 100, &information) == STATUS_SUCCESS);
    completion_raises = 1;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 3, offset, 0, 0, &information) == STATUS_UNSUCCESSFUL);
    assert(write_aborts == 3 && write_releases == 2 && irp.MdlAddress == NULL && information == 0);
    completion_raises = 0;

    offset.QuadPart = 100;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 0, offset, 1, 100, &information) == STATUS_END_OF_FILE);
    assert(ext4win_cache_mdl_transfer(&file, &irp, 2, offset, 1, 100, &information) == STATUS_INVALID_PARAMETER);
    assert(ext4win_cache_mdl_transfer(&file, &irp, 0, offset, 0, 100, &information) == STATUS_SUCCESS);
    offset.QuadPart = 99;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 2, offset, 2, 100, &information) == STATUS_INVALID_PARAMETER);
    offset.QuadPart = -1;
    assert(ext4win_cache_mdl_transfer(&file, &irp, 0, offset, 1, 100, &information) == STATUS_INVALID_PARAMETER);
    assert(reads == 3 && prepares == 4 && irp.MdlAddress == NULL);
    return 0;
}

#ifndef EXT4WIN_CACHE_WRITE_ADMISSION_H
#define EXT4WIN_CACHE_WRITE_ADMISSION_H

/* The passive work envelope retains the FILE_OBJECT, stream and IRP through
 * this wait. No filesystem resource is held: lazy writeback must remain able
 * to release dirty-page pressure. The non-alertable KernelMode wait keeps this
 * kernel stack resident until the sole Cc callback has signaled its event. */
static VOID
ext4win_cache_write_ready(PVOID context, PVOID unused)
{
    UNREFERENCED_PARAMETER(unused);
    (VOID)KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);
}

/* CanIWrite retry and DeferWrite retry are distinct observations: a request
 * can lose admission while acquiring MainResource without ever being deferred. */
typedef enum {
    EXT4WIN_CACHE_WRITE_FIRST,
    EXT4WIN_CACHE_WRITE_CHECKED,
    EXT4WIN_CACHE_WRITE_DEFERRED
} EXT4WIN_CACHE_WRITE_ADMISSION;

static BOOLEAN
ext4win_cache_try_write(PFILE_OBJECT file, ULONG length, BOOLEAN wait,
    EXT4WIN_CACHE_WRITE_ADMISSION *admission)
{
    BOOLEAN accepted = CcCanIWrite(file, length, wait, *admission != EXT4WIN_CACHE_WRITE_FIRST);
    if (*admission == EXT4WIN_CACHE_WRITE_FIRST) { *admission = EXT4WIN_CACHE_WRITE_CHECKED; }
    return accepted;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ext4win_cache_wait_for_write(PFILE_OBJECT file, ULONG length, EXT4WIN_CACHE_WRITE_ADMISSION *admission)
{
    while (!ext4win_cache_try_write(file, length, TRUE, admission)) {
        KEVENT ready;
        KeInitializeEvent(&ready, NotificationEvent, FALSE);
        CcDeferWrite(file, ext4win_cache_write_ready, &ready, NULL, length,
            *admission == EXT4WIN_CACHE_WRITE_DEFERRED);
        *admission = EXT4WIN_CACHE_WRITE_DEFERRED;
        /* An indefinite, non-alertable kernel event wait has only a successful
         * completion. Immediate callback delivery is retained by NotificationEvent. */
        (VOID)KeWaitForSingleObject(&ready, Executive, KernelMode, FALSE, NULL);
    }
}

#endif

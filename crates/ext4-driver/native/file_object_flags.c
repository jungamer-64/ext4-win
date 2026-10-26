#include <ntifs.h>
#include "file_object_flags.h"
#include "disk_accounting.h"

C_ASSERT(sizeof(((FILE_OBJECT *)0)->Flags) == sizeof(LONG));
C_ASSERT((FIELD_OFFSET(FILE_OBJECT, Flags) % TYPE_ALIGNMENT(LONG)) == 0);

_Use_decl_annotations_
ULONG NTAPI ext4win_file_flags(PFILE_OBJECT file)
{
    return ReadULongNoFence(&file->Flags);
}

_Use_decl_annotations_
VOID NTAPI ext4win_file_set_flags(PFILE_OBJECT file, ULONG flags)
{
    (VOID)InterlockedOr((volatile LONG *)&file->Flags, (LONG)flags);
}

_Use_decl_annotations_
VOID NTAPI ext4win_file_clear_flags(PFILE_OBJECT file, ULONG flags)
{
    (VOID)InterlockedAnd((volatile LONG *)&file->Flags, (LONG)~flags);
}

#include <stdint.h>
#include <stddef.h>

void *memset(void *storage, int value, size_t size) {
    volatile uint8_t *bytes = storage;
    for (size_t i = 0; i < size; ++i) { bytes[i] = (uint8_t)value; }
    return storage;
}

typedef uint32_t ULONG;
typedef uint32_t ACCESS_MASK;
typedef uint8_t BOOLEAN;
typedef int8_t KPROCESSOR_MODE;
typedef struct { ULONG LowPart; int32_t HighPart; } LUID;
typedef struct { LUID Luid; ULONG Attributes; } LUID_AND_ATTRIBUTES;
typedef struct { ULONG PrivilegeCount; ULONG Control; LUID_AND_ATTRIBUTES Privilege[1]; } PRIVILEGE_SET;
typedef struct { ULONG PrivilegeCount; ULONG Control; LUID_AND_ATTRIBUTES Privilege[3]; } INITIAL_PRIVILEGE_SET, *PINITIAL_PRIVILEGE_SET;
typedef struct { BOOLEAN Backup; BOOLEAN Restore; } SECURITY_SUBJECT_CONTEXT, *PSECURITY_SUBJECT_CONTEXT;
#define READ_CONTROL 0x20000U
#define WRITE_DAC 0x40000U
#define WRITE_OWNER 0x80000U
#define ACCESS_SYSTEM_SECURITY 0x1000000U
#define FILE_GENERIC_READ 0x120089U
#define FILE_GENERIC_WRITE 0x120116U
#define FILE_TRAVERSE 0x20U
#define DELETE 0x10000U
#define MAXIMUM_ALLOWED 0x2000000U
#define FILE_OPEN 1U
#define FILE_OPEN_IF 3U
#define FILE_OVERWRITE_IF 5U
#define SE_BACKUP_PRIVILEGE 17U
#define SE_RESTORE_PRIVILEGE 18U
#define PRIVILEGE_SET_ALL_NECESSARY 1U
#define SE_PRIVILEGE_USED_FOR_ACCESS 0x80000000U

static void RtlZeroMemory(void *storage, size_t size) {
    uint8_t *bytes = storage;
    for (size_t i = 0; i < size; ++i) { bytes[i] = 0; }
}
static LUID RtlConvertLongToLuid(ULONG privilege) { LUID id = { privilege, 0 }; return id; }
static BOOLEAN SePrivilegeCheck(PRIVILEGE_SET *required, PSECURITY_SUBJECT_CONTEXT subject, KPROCESSOR_MODE mode) {
    (void)mode;
    BOOLEAN enabled = required->Privilege[0].Luid.LowPart == SE_BACKUP_PRIVILEGE ? subject->Backup : subject->Restore;
    if (enabled) { required->Privilege[0].Attributes = SE_PRIVILEGE_USED_FOR_ACCESS; }
    return enabled;
}
#include "backup_restore.h"

int main(void) {
    SECURITY_SUBJECT_CONTEXT subject = { 0, 0 };
    INITIAL_PRIVILEGE_SET used;
    if (ext4win_privileged_create_access(&subject, 1, FILE_OPEN, MAXIMUM_ALLOWED, &used) != 0 || used.PrivilegeCount != 0) { return 1; }
    subject.Backup = 1;
    for (ULONG disposition = 0; disposition < 6; ++disposition) {
        ACCESS_MASK expected = (disposition == 1 || disposition == 3 || disposition == 5) ? 1U : 0U;
        if (ext4win_privileged_create_access(&subject, 1, disposition, 1U, &used) != expected || used.PrivilegeCount != expected) { return 2; }
    }
    if (ext4win_privileged_create_access(&subject, 1, FILE_OPEN, 2U, &used) != 0 || used.PrivilegeCount != 0) { return 3; }
    subject.Backup = 0; subject.Restore = 1;
    if (ext4win_privileged_create_access(&subject, 1, 2, DELETE | WRITE_OWNER, &used) != (DELETE | WRITE_OWNER) || used.PrivilegeCount != 1 || used.Privilege[0].Luid.LowPart != 18) { return 4; }
    subject.Backup = 1;
    ACCESS_MASK expected = 0x11F01BFU;
    if (ext4win_privileged_create_access(&subject, 1, FILE_OPEN, MAXIMUM_ALLOWED, &used) != expected || used.PrivilegeCount != 2) { return 5; }
    if (used.Privilege[0].Attributes != SE_PRIVILEGE_USED_FOR_ACCESS || used.Privilege[1].Attributes != SE_PRIVILEGE_USED_FOR_ACCESS) { return 6; }
    return 0;
}

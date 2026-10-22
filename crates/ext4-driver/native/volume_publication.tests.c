/* Execute the production publication boundary with independently controlled WDK
 * outcomes. Windows PnP/Mount Manager behavior is checked by the live VHDX gate. */
#define assert(condition) do { if (!(condition)) { __builtin_trap(); } } while (0)
#define _IRQL_requires_(level)
#define _In_
#define NTAPI
#define NULL ((void *)0)
#define TRUE 1
#define NT_SUCCESS(status) ((status) >= 0)
#define STATUS_SUCCESS 0
#define STATUS_OBJECT_NAME_EXISTS 0x40000000
#define STATUS_NO_SUCH_DEVICE (-1)
#define STATUS_FAILURE (-2)

typedef int NTSTATUS;
typedef struct { unsigned identity; } DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct { unsigned identity; } GUID;
typedef struct { unsigned short *Buffer; } UNICODE_STRING;

static DEVICE_OBJECT lower, pdo;
static const GUID volume_class = {73};
static unsigned short interface_name[] = {1, 2, 3, 0};
static NTSTATUS registration_status, enable_status;
static unsigned references, names, registrations, enables;
static int removed;

static PDEVICE_OBJECT IoGetDeviceAttachmentBaseRef(PDEVICE_OBJECT device)
{
    assert(device == &lower);
    if (removed) { return NULL; }
    references++;
    return &pdo;
}

static NTSTATUS IoRegisterDeviceInterface(PDEVICE_OBJECT device,
    const GUID *kind, UNICODE_STRING *reference, UNICODE_STRING *name)
{
    assert(device == &pdo && references == 1);
    assert(kind == &volume_class && reference == NULL);
    registrations++;
    if (NT_SUCCESS(registration_status)) {
        assert(names == 0);
        names++;
        name->Buffer = interface_name;
    }
    return registration_status;
}

static NTSTATUS IoSetDeviceInterfaceState(UNICODE_STRING *name, int enable)
{
    assert(name->Buffer == interface_name && enable == TRUE);
    assert(references == 1 && names == 1);
    enables++;
    return enable_status;
}

static void RtlFreeUnicodeString(UNICODE_STRING *name)
{
    assert(names == 1 && name->Buffer == interface_name);
    names--;
    name->Buffer = NULL;
}

static void ObDereferenceObject(PDEVICE_OBJECT device)
{
    assert(device == &pdo && references == 1 && names == 0);
    references--;
}

#include "volume_publication.h"

int main(void)
{
    registration_status = enable_status = STATUS_SUCCESS;
    assert(ext4win_publish_volume_interface(&lower, &volume_class) == STATUS_SUCCESS);
    assert(registrations == 1 && enables == 1 && references == 0 && names == 0);

    registration_status = enable_status = STATUS_OBJECT_NAME_EXISTS;
    assert(ext4win_publish_volume_interface(&lower, &volume_class) == STATUS_OBJECT_NAME_EXISTS);
    assert(registrations == 2 && enables == 2 && references == 0 && names == 0);

    registration_status = STATUS_FAILURE;
    assert(ext4win_publish_volume_interface(&lower, &volume_class) == STATUS_FAILURE);
    assert(registrations == 3 && enables == 2 && references == 0 && names == 0);

    registration_status = STATUS_SUCCESS;
    enable_status = STATUS_FAILURE;
    assert(ext4win_publish_volume_interface(&lower, &volume_class) == STATUS_FAILURE);
    assert(registrations == 4 && enables == 3 && references == 0 && names == 0);

    removed = 1;
    assert(ext4win_publish_volume_interface(&lower, &volume_class) == STATUS_NO_SUCH_DEVICE);
    assert(registrations == 4 && enables == 3 && references == 0 && names == 0);
    return 0;
}

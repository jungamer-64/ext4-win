"""Explicit, read-only Windows volume queries and configured service identity.

Volume queries are synchronous and may wait inside the filesystem driver.
Configured ImagePath hashing does not identify the image loaded in kernel memory.
No service start/stop, control IOCTL, registry write or storage write is issued.
"""

import ctypes
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import time


def require_windows():
    if os.name != "nt":
        raise OSError("this diagnostic requires Windows")


def service_identity(name):
    require_windows()
    import winreg
    if not re.fullmatch(r"[\w.-]+", name):
        raise ValueError("expected one service name, without a registry path")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\" + name) as key:
        try:
            image, kind = winreg.QueryValueEx(key, "ImagePath")
        except FileNotFoundError as error:
            raise ValueError(f"driver service {name!r} has no explicit ImagePath to hash") from error
        service_type = winreg.QueryValueEx(key, "Type")[0]
    if service_type not in (1, 2) or kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        raise ValueError("expected a kernel or filesystem driver ImagePath")
    path = Path(resolve_driver_path(image, os.environ["SystemRoot"]))
    data = path.read_bytes()
    return {"service": name, "configured_image": str(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "scope": "Configured service image on disk; loaded kernel image is unverified."}


def resolve_driver_path(image, system_root):
    value = os.path.expandvars(image).strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    if value.lower().startswith("\\systemroot\\"):
        value = str(PureWindowsPath(system_root) / value[12:])
    elif value.startswith("\\??\\"):
        value = value[4:]
    path = PureWindowsPath(value)
    if not path.drive and not path.root and path.parts and path.parts[0].lower() == "system32":
        path = PureWindowsPath(system_root) / path
    if not path.is_absolute():
        raise ValueError("driver ImagePath must resolve to an absolute path")
    return path


class IoStatusBlock(ctypes.Structure):
    # NTSTATUS occupies the first DWORD of a pointer-sized union.
    _fields_ = [("status_or_pointer", ctypes.c_void_p), ("information", ctypes.c_size_t)]


def volume_information(path):
    require_windows()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    native = ctypes.WinDLL("ntdll")
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    native.NtQueryVolumeInformationFile.argtypes = [w.HANDLE, ctypes.POINTER(IoStatusBlock), w.LPVOID, w.ULONG, w.ULONG]
    native.NtQueryVolumeInformationFile.restype = ctypes.c_int32
    handle = kernel.CreateFileW(path, 0x80, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    records = []
    try:
        for name, number in [("volume", 1), ("size", 3), ("device", 4), ("attributes", 5), ("full-size", 7)]:
            buffer, status_block = ctypes.create_string_buffer(4096), IoStatusBlock()
            started = time.perf_counter()
            status = native.NtQueryVolumeInformationFile(handle, ctypes.byref(status_block), buffer, len(buffer), number)
            if status_block.information > len(buffer):
                raise ValueError("native query returned a length outside its buffer")
            records.append({"class": name, "class_number": number,
                            "ntstatus": f"0x{status & 0xFFFFFFFF:08x}", "success": status >= 0,
                            "returned_bytes": status_block.information,
                            "data_hex": buffer.raw[:status_block.information].hex(),
                            "milliseconds": (time.perf_counter() - started) * 1000})
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())
    return {"path": path, "queries": records, "success": all(item["success"] for item in records)}

"""Independent bitwise ext4 extent-block checksum diagnostic.

The caller supplies the exact superblock, inode identity/generation and external
extent block. This checks the checksum boundary, not filesystem consistency.
"""

import struct


def crc32c(seed, data):
    for byte in data:
        seed ^= byte
        for _ in range(8):
            seed = (seed >> 1) ^ (0x82F63B78 if seed & 1 else 0)
    return seed


def check_extent(superblock, inode_number, generation, block):
    if len(superblock) != 1024 or struct.unpack_from("<H", superblock, 56)[0] != 0xEF53:
        raise ValueError("expected a 1024-byte ext superblock")
    incompat = struct.unpack_from("<I", superblock, 96)[0]
    ro_compat = struct.unpack_from("<I", superblock, 100)[0]
    if not ro_compat & 0x400 or superblock[0x175] != 1:
        raise ValueError("superblock does not declare CRC32C metadata checksums")
    block_log = struct.unpack_from("<I", superblock, 24)[0]
    if block_log > 6 or len(block) != 1024 << block_log:
        raise ValueError("extent block length disagrees with superblock geometry")
    if not 1 <= inode_number <= 0xFFFFFFFF or not 0 <= generation <= 0xFFFFFFFF:
        raise ValueError("inode number or generation outside the on-disk range")
    magic, entries, maximum, depth, _ = struct.unpack_from("<HHHHI", block)
    tail = 12 + maximum * 12
    if magic != 0xF30A or not maximum or entries > maximum or depth > 5 or tail + 4 > len(block):
        raise ValueError("invalid external extent header or checksum tail")
    seed = (struct.unpack_from("<I", superblock, 0x270)[0] if incompat & 0x2000
            else crc32c(0xFFFFFFFF, superblock[104:120]))
    seed = crc32c(crc32c(seed, struct.pack("<I", inode_number)), struct.pack("<I", generation))
    actual = crc32c(seed, block[:tail])
    expected = struct.unpack_from("<I", block, tail)[0]
    return {"matches": actual == expected, "stored_crc32c": f"{expected:08x}",
            "computed_crc32c": f"{actual:08x}", "tail_byte_offset": tail,
            "entries": entries, "maximum": maximum, "depth": depth}

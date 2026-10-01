"""AMD64 PE fixed-frame inspection, independent of a preferred load address.

Version-one and version-two unwind records are interpreted; unsupported records fail
explicitly. Frames describe fixed prolog stack usage, excluding the return
address, dynamic allocation, callees, interrupts, and runtime stack occupancy.
Format authority: https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
"""

import re
import struct


class PeImage:
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("missing DOS signature")
        pe = self.unpack("<I", 0x3C)[0]
        if self.take(pe, 4) != b"PE\0\0" or self.unpack("<H", pe + 4)[0] != 0x8664:
            raise ValueError("expected an AMD64 PE image")
        count = self.unpack("<H", pe + 6)[0]
        optional_size = self.unpack("<H", pe + 20)[0]
        optional = pe + 24
        self.take(optional, optional_size)
        if optional_size < 144 or self.unpack("<H", optional)[0] != 0x20B:
            raise ValueError("missing PE32+ exception directory")
        if self.unpack("<I", optional + 108)[0] < 4:
            raise ValueError("no exception directory")
        self.image_base = self.unpack("<Q", optional + 24)[0]
        self.sections = []
        for index in range(count):
            entry = optional + optional_size + 40 * index
            self.take(entry, 40)
            virtual_size, rva, raw_size, raw = self.unpack("<IIII", entry + 8)
            self.take(raw, raw_size)
            self.sections.append((rva, raw_size, raw))
        self.pdata, self.pdata_size = self.unpack("<II", optional + 136)

    def take(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError("truncated PE data")
        return self.data[offset:offset + size]

    def unpack(self, layout, offset):
        return struct.unpack(layout, self.take(offset, struct.calcsize(layout)))

    def at(self, rva, size):
        matches = [raw + rva - start for start, length, raw in self.sections
                   if start <= rva and rva + size <= start + length]
        if len(matches) != 1:
            raise ValueError(f"unmapped or ambiguous file-backed RVA {rva:#x}")
        return matches[0]

    def fixed_stack(self, rva, active=frozenset()):
        # A finite record chain is required; do not turn cycles into zero usage.
        if rva in active or len(active) >= 128 or rva % 4:
            raise ValueError("invalid or excessive chained unwind records")
        offset = self.at(rva, 4)
        version_flags, _, count, _ = self.take(offset, 4)
        version, flags = version_flags & 7, version_flags >> 3
        if version not in (1, 2) or flags & ~7 or (flags & 4 and flags & 3):
            raise ValueError("unsupported unwind version or flags")
        codes = self.take(self.at(rva + 4, 2 * count), 2 * count)
        index, total = 0, 0
        while index < count:
            operation, info = codes[2 * index + 1] & 15, codes[2 * index + 1] >> 4
            index += 1
            extra = 0
            if operation == 0:
                total += 8
            elif operation == 1 and info in (0, 1):
                extra = 1 if info == 0 else 2
                if index + extra > count:
                    raise ValueError("truncated large-allocation unwind code")
                amount = int.from_bytes(codes[2 * index:2 * (index + extra)], "little")
                total += amount * 8 if info == 0 else amount
            elif operation == 2:
                total += info * 8 + 8
            elif operation == 3 and info == 0:
                pass
            elif operation == 6 and version == 2:
                # Each version-two epilog descriptor occupies one slot and
                # describes code position, adding no prolog stack allocation.
                pass
            elif operation in (4, 8):
                extra = 1
            elif operation in (5, 9):
                extra = 2
            elif operation == 10 and info in (0, 1):
                total += 40 + 8 * info
            else:
                raise ValueError(f"unsupported unwind opcode {operation}, info {info}")
            index += extra
            if index > count:
                raise ValueError("truncated unwind operands")
        if flags & 4:
            chain = self.at(rva + 4 + ((count + 1) & ~1) * 2, 12)
            begin, end, parent = self.unpack("<III", chain)
            if begin >= end:
                raise ValueError("invalid chained function range")
            total += self.fixed_stack(parent, active | {rva})
        return total

    def frames(self, map_text):
        if not self.pdata or not self.pdata_size or self.pdata_size % 12:
            raise ValueError("missing or malformed runtime function table")
        symbols = {}
        for line in map_text.splitlines():
            match = re.match(r"\s+[0-9a-fA-F]+:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})\s", line)
            if match:
                address = int(match[2], 16) - self.image_base
                symbols.setdefault(address, []).append(match[1])
        records, previous = [], -1
        for index in range(self.pdata_size // 12):
            entry = self.at(self.pdata + 12 * index, 12)
            begin, end, unwind = self.unpack("<III", entry)
            if begin >= end or begin <= previous or not unwind:
                raise ValueError("invalid runtime function entry")
            previous = begin
            self.at(begin, end - begin)
            records.append({"begin_rva": begin, "end_rva": end,
                            "fixed_stack_bytes": self.fixed_stack(unwind),
                            "symbols": symbols.get(begin, [])})
        return sorted(records, key=lambda frame: frame["fixed_stack_bytes"], reverse=True)

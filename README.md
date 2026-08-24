# ext4-win

`ext4-win` is a native read-write ext4 file-system driver for Windows. It
combines a portable, `no_std` ext4 implementation with a Windows kernel driver
that exposes ext4 volumes through the Windows file-system interface.

The ext4 on-disk format is the external authority. Internal Rust APIs and state
models are free to evolve so that ownership, validation, and durability remain
explicit.

## Ext4 capabilities

The implemented file-system surface includes:

- file and directory creation, lookup, enumeration, rename, and removal;
- extent-backed reads and writes, sparse extension, truncation, and allocation;
- hard links, native symbolic links, POSIX metadata, timestamps, and volume
  labels;
- inline and external extended attributes;
- indexed directories and BIGALLOC allocation geometry;
- fscrypt key handling and encrypted namespace and data access;
- fs-verity enablement and verified reads; and
- Windows extended attributes, reparse points, security information, and file
  metadata projected onto ext4 storage.

Mutations are journaled and recovered before a mounted volume is published.
Both internal and external journals are represented by the core mount and
durability protocols.

This is not an exhaustive feature-flag matrix. `ext4-core` mount validation is
the authority for whether a particular volume's feature set, geometry, and
journal configuration are accepted. The project does not claim compatibility
with every ext4 volume.

## Architecture

| Component | Responsibility |
| --- | --- |
| `ext4-core` | Validates ext4 disk structures and owns traversal, allocation, protected-file handling, journal recovery, and transactional mutation without depending on Windows types. |
| `ext4win` | Translates Windows kernel requests into typed core operations and owns IRP, storage, cancellation, mount, and driver lifetime boundaries. |
| `xtask` and `production-reachability` | Define the canonical development gates and bind release evidence to the exact signed driver artifact. |

The dependency direction keeps ext4 semantics in the portable core while the
driver contains Windows-specific representation and lifecycle concerns.

## Build and evaluate

The portable ext4 implementation and repository tooling can be checked on
Windows, Linux, or macOS:

```console
cargo xtask verify-portable
```

Checking the kernel driver requires Windows with the configured MSVC and WDK
toolchain:

```console
cargo xtask verify-driver
```

Live evaluation is deliberately limited to a new disposable VHDX on a
dedicated, elevated Windows host:

```console
cargo xtask check-live-driver-host
cargo xtask verify-live-vhdx
```

The workflow does not accept a physical disk path or disk number. It builds an
identity-bound driver bundle, creates and formats its own VHDX, verifies the
DriverStore image, exercises file-system operations under Driver Verifier, and
requires service, package, and VHDX cleanup.

See [DEVELOPMENT.md](DEVELOPMENT.md) for prerequisites, the complete command
matrix, ext4 interoperability coverage, production release evidence, and live
validation boundaries.

## Assurance boundaries

- Portable verification covers the host-independent core and tooling; it does
  not validate a Windows kernel artifact.
- Driver verification checks the WDK-facing crate but does not prove that a
  signed package contains the analyzed build.
- Production verification binds source, LLVM IR, link map, SYS, CAT, and INF
  into one signed evidence bundle; it does not prove which image Windows loaded.
- Live VHDX verification checks the loaded artifact and observable file-system
  behavior for its generated test volume. It is not evidence for an arbitrary
  physical volume or an untested ext4 feature combination.

# Development

The workspace separates the portable ext4 domain from the Windows kernel
boundary. Default Cargo commands select the host-independent members:
`ext4-core`, `production-reachability`, and `xtask`. Use the repository tasks
below instead of substituting generic Cargo commands for a canonical gate.

## Verification commands

| Command | Host requirements | What it establishes |
| --- | --- | --- |
| `cargo xtask verify-portable` | Windows, Linux, or macOS | Checks formatting and all portable targets, then runs the portable tests and Clippy. |
| `cargo xtask verify-driver` | Windows with MSVC and WDK configured | Checks, tests, lints, and builds rustdoc for the `ext4win` kernel-driver crate. It does not build a signed release package. |
| `cargo xtask verify-journal-interop` | Native Linux or Windows with WSL; e2fsprogs | Exercises ext4 mutation and recovery against independently generated `debugfs` and `e2fsck` evidence. |
| `cargo xtask verify-journal-fixture-provenance` | Native Linux or Windows with WSL; root loop-device authority and the manifest-pinned e2fsprogs release | Regenerates the tracked external-journal fixtures and requires byte-for-byte and digest equality. |
| `cargo xtask verify-production-driver` | Windows with MSVC, WDK, `cargo-wdk`, WSL, and e2fsprogs | Runs the development and interoperability gates, builds and signs one identity-bound package, and verifies release reachability. |
| `cargo xtask check-live-driver-host` | Dedicated elevated Windows host with Hyper-V PowerShell, WSL/e2fsprogs, and Driver Verifier configured | Performs the read-only preflight for disposable live validation. |
| `cargo xtask verify-live-vhdx` | A host that passes the live preflight | Builds a verified bundle and exercises it only against a newly created disposable VHDX. |
| `cargo xtask cleanup-live-vhdx-session <session-id>` | Dedicated elevated Windows host | Reconciles an interrupted session and removes only resources whose recorded identities still match. |

## Ext4 durability and interoperability

`verify-journal-interop` treats e2fsprogs as an independent oracle rather than
generating expected results through the production core. Every scenario starts
from a newly formatted or freshly copied image. The 4 KiB profile covers file
and directory creation, multi-block writes, growth, truncation, rename, hard
links, unlink, and xattr creation, replacement, and removal. The 4 KiB-block/
16 KiB-cluster BIGALLOC profile additionally covers allocation, cluster reuse,
and free-space accounting.

Journal recovery is one part of this ext4-wide gate. Linux-generated JBD2
records exercise supported block sizes, checksum layouts, 64-bit block numbers,
and revokes. The external-journal profile groups rename, sparse-extension write,
and xattr update into one mutation and evaluates interrupted home-block writes
and flush cuts. Recovery is accepted only when `e2fsck -f` is clean and the
observable namespace, content, links, xattrs, and allocation state are wholly
old or wholly new.

The crash model assumes atomic 512-byte sectors. Writes may be absent, may
persist at a sector-aligned prefix, or may persist completely. Successful
flushes preserve prior write ordering and make durable only the target device,
so an external journal and its filesystem image have independent volatile and
durable states.

Supported-feature acceptance remains owned by core mount validation. These
scenarios describe tested behavior; they do not create a second feature matrix.

## Production release evidence

`verify-production-driver` is the sole release umbrella. It first runs
`verify-portable`, `verify-driver`, and `verify-journal-interop`. It then creates
one build identity, builds and signs the package, binds the LLVM IR, link map,
and driver image to that identity, runs the production reachability gate, and
rejects concurrent source changes. It fails explicitly on macOS and Linux
instead of compiling a non-Windows driver shim.

Successful bundles are atomically published below
`target/verified-production/<artifact-id>/`. The versioned manifest binds the
IR, MAP, SYS, CAT, and INF hashes to the exact source snapshot, target, profile,
rustflags, and rustc, LLVM, Cargo, `cargo-wdk`, and WDK versions. The production
command neither reuses portable artifacts nor accepts stale release output.

## CI and live-driver boundaries

CI runs `verify-portable` on Windows, Ubuntu, and macOS and runs ext4
interoperability on Ubuntu. The production job requires the dedicated
`[self-hosted, Windows, X64, ext4-win-wdk]` runner and is serialized globally.
That runner contract includes MSVC, WDK, `cargo-wdk`, WSL, and e2fsprogs.

A green production job proves the signed bundle and its reachability evidence.
It does not prove which SYS Windows loaded, that Driver Verifier observed that
image, or that mount and teardown succeeded. Live validation must compare the
loaded DriverStore SYS hash with the verified bundle and treat a missing
Verifier configuration, cleanup failure, or hash mismatch as failure.

`verify-live-vhdx` does not accept a disk path or disk number. It creates one
fixed-size VHDX below `target/live-vhdx-sessions/<session-id>/`, bounds WSL
device discovery to the device introduced by that VHDX, and unmounts the device
from WSL before Windows-driver access. It selects the newly published OEM INF
from structured PnPUtil XML and verifies the exported SYS hash before and after
service start.

The live scenario requires file create, read, write, rename, hard link,
patterned enumeration, durable flush, clean dismount, driver unload, package
removal, and VHDX removal to succeed. Every external side effect is preceded by
a durably flushed session-manifest snapshot. Cleanup revalidates the verified
bundle identity, SYS hash, OEM INF, VHDX path, disk unique ID, and service name
before acting. Physical disks remain permanently outside this workflow.

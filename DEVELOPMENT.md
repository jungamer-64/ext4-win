# Development

The repository pins `nightly-2026-08-10`. The default workspace members are
host-independent. On Windows, macOS, or Linux, run the complete portable gate
with:

```console
cargo xtask verify-portable
```

This checks formatting, compiles all portable targets, runs their tests, and
runs Clippy. Plain `cargo test` also selects only the portable default members:
`ext4-core`, `production-reachability`, and `xtask`.

The driver-specific development gate is:

```console
cargo xtask verify-driver
```

It checks the driver crate, runs at least 265 unit tests, runs Clippy over all
driver targets, and builds rustdoc. It is distinct from a signed production
build and does not by itself prove WDK packaging or release reachability.

JBD2 interoperability is independently checked with:

```console
cargo xtask verify-journal-interop
```

This requires e2fsprogs on native Linux or WSL. The core implementation never
generates its own oracle result: `debugfs` and `e2fsck` establish the external
filesystem and journal evidence. Each scenario starts from a newly formatted or
freshly copied image. The 4 KiB internal profile covers create, multi-block
write, grow, shrink, rename, hard link, unlink, and xattr set/update/delete.
The 4 KiB-block/16 KiB-cluster BIGALLOC profile covers allocation, truncate,
unlink, cluster reuse, and free-space accounting. The 4 KiB external-journal
profile commits rename, sparse-extension write, and xattr update together and
models interrupted home-block writes as an ordered 512-byte prefix of the new
image followed by the old suffix. The next mount must replay that dirty journal
to the complete new state, after which `e2fsck` must accept the filesystem.

Building and signing the kernel driver remains a Windows-only operation because
it requires MSVC, the Windows Driver Kit, and `cargo-wdk`. On a configured
Windows host, run:

```console
cargo xtask verify-production-driver
```

This is the only release umbrella. It first runs `verify-portable`,
`verify-driver`, and `verify-journal-interop`; then it creates one build
identity, builds and signs the package, binds the LLVM IR, link map, and driver
image to that identity, runs the production reachability gate, and rejects
concurrent source changes. It fails explicitly on macOS and Linux instead of
compiling a non-Windows driver shim.

Successful bundles are atomically published below
`target/verified-production/<artifact-id>/`. The versioned manifest binds IR,
MAP, SYS, CAT, and INF hashes to the exact source snapshot, target, profile,
rustflags, and rustc/LLVM/Cargo/cargo-wdk/WDK versions. The production command
does not reuse a portable artifact and does not accept a stale release output.

## CI and host boundaries

CI runs `verify-portable` on Windows, Ubuntu, and macOS and runs journal
interoperability on Ubuntu. The production job requires the dedicated
`[self-hosted, Windows, X64, ext4-win-wdk]` runner and is serialized globally.
That runner contract includes MSVC, WDK, cargo-wdk, WSL, and e2fsprogs.

Live DriverStore validation is a separate manual assurance boundary. A green
self-hosted production job proves the signed bundle and reachability evidence;
it does not prove which SYS Windows loaded, that Driver Verifier observed the
driver, or that mount and teardown succeeded. Live validation must compare the
loaded DriverStore SYS hash with the verified bundle and treat a missing
Verifier configuration, cleanup failure, or hash mismatch as failure.

On a dedicated host, the read-only preflight is:

```console
cargo xtask check-live-driver-host
```

It requires elevation, Hyper-V PowerShell, WSL/e2fsprogs, an explicit
`ext4win.sys` Driver Verifier configuration, and absence of an existing
ext4win service or DriverStore package. The full destructive command is:

```console
cargo xtask verify-live-vhdx
```

The command does not accept a disk path or disk number. It first creates a
verified production bundle and then creates only a new fixed-size VHDX below
`target/live-vhdx-sessions/<session-id>/`. WSL device discovery is bounded to
the one new device introduced by that VHDX, and WSL is explicitly unmounted
before the disk is reattached for Windows-driver access.

Before service start and again after service start, the workflow consumes
PnPUtil XML inventory, selects the exact newly published OEM INF, exports that
package, and compares its SYS hash with the production manifest. It does not
parse localized PnPUtil display text. File create/read/write, rename, hard
link, patterned enumeration, durable flush, clean volume dismount, driver
unload, package removal, and VHDX removal must all succeed.

Every external side effect is preceded by a new, durably flushed
`session-v1-NNNN.manifest` snapshot. An interrupted session is reconciled with:

```console
cargo xtask cleanup-live-vhdx-session <session-id>
```

Cleanup resolves only the generated session directory and refuses to act
unless the verified bundle identity and SYS hash, exact VHDX path, recorded
disk unique ID, service name, and structured-inventory OEM INF still match.
Physical disks remain permanently outside this workflow.

## Crash model

Crash-consistency assurance assumes 512-byte atomic sectors. Writes may be
absent, may persist at a sector-aligned prefix, or may persist completely.
Successful flushes preserve prior write ordering and make durable only the
target device. The filesystem image and external-journal image therefore have
independent volatile and durable states. Recovery is accepted only when
`e2fsck -f` is clean and externally observable path, content, link, xattr, and
allocation state is wholly old or wholly new; mixed state is rejected.

Supported-feature acceptance remains owned by the core mount validation. This
document records verification boundaries and does not maintain a second
feature matrix.

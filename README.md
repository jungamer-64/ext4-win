# ext4-win

`ext4-win` is a native Windows ext4 file-system driver backed by the portable
`ext4-core` implementation. The repository follows the ext4 on-disk and JBD2
contracts as external authorities; internal Rust APIs are free to evolve when
that produces a safer ownership or state model.

## Verification

The repository pins `nightly-2026-08-10`. The canonical development gates are:

```console
cargo xtask verify-portable
cargo xtask verify-driver
cargo xtask verify-journal-interop
```

`verify-portable` runs on Windows, Linux, and macOS. `verify-driver` requires a
Windows host with the MSVC/WDK environment needed by `windows-drivers-rs`.
`verify-journal-interop` requires Linux e2fsprogs, either natively or through
WSL. It creates fresh 4 KiB and 4 KiB/16 KiB BIGALLOC images, drives typed
ext4-core namespace/data/xattr mutations, and uses `debugfs` plus `e2fsck` as
independent oracles. The 4 KiB external-journal profile additionally exercises
rename/write/xattr recovery at every modeled write-prefix and flush cut.

The sole release authority is:

```console
cargo xtask verify-production-driver
```

It runs all three gates above before building and signing the driver, checks
production reachability against identity-matched LLVM IR, link map, and SYS,
and publishes an immutable evidence bundle at
`target/verified-production/<artifact-id>/`. `manifest-v1.txt` records SHA-256
hashes for IR, MAP, SYS, CAT, and INF together with the source snapshot,
rustc/LLVM/Cargo/cargo-wdk/WDK versions, target, profile, and exact rustflags.
A portable build is not production-driver validation.

## Durability boundary

The crash model assumes atomic 512-byte sectors and preservation of write
ordering established before each successful flush. A flush makes durable only
the device it targets; an external journal and its filesystem image therefore
have independent volatile and durable states. Acceptance after any modeled
cut point requires a clean `e2fsck -f` result and an observable namespace and
metadata state equal to either the complete old state or the complete new
state. Mixed allocation, link, or xattr state is invalid.

See [DEVELOPMENT.md](DEVELOPMENT.md) for host contracts, CI boundaries, and
live-driver assurance limits.

The manual live commands are:

```console
cargo xtask check-live-driver-host
cargo xtask verify-live-vhdx
cargo xtask cleanup-live-vhdx-session <session-id>
```

They accept no physical disk path or disk number. `verify-live-vhdx` creates
its own fixed-size disposable VHDX, formats it through WSL, unmounts it from
WSL before Windows access, verifies the exported DriverStore SYS hash before
and after service start, exercises file-system behavior under Driver Verifier,
and requires complete service/package/VHDX cleanup. Each external side effect
is preceded by a durable append-only session manifest. Cleanup revalidates the
session artifact identity, OEM INF, VHDX path, and disk unique ID before acting.

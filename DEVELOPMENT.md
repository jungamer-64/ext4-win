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
| `cargo xtask verify-fuzz-replay` | Host with the repository-pinned cargo-fuzz installed | Discovers every declared fuzz target and replays its tracked corpus once under the bounded fuzz harness. |
| `cargo xtask verify-journal-interop` | Native Linux or Windows with WSL; e2fsprogs | Exercises ext4 mutation and recovery against independently generated `debugfs` and `e2fsck` evidence. |
| `cargo xtask verify-htree-interop` | Native Linux or Windows with WSL; e2fsprogs and root loop-mount authority | Exercises bounded HTree lookup, paging, and local mutation against independently generated ext4 images. |
| `cargo xtask verify-journal-fixture-provenance` | Native Linux or Windows with WSL; root loop-device authority and the manifest-pinned e2fsprogs release | Regenerates the tracked external-journal fixtures and requires byte-for-byte and digest equality. |
| `cargo xtask verify-production-driver` | Windows with MSVC, WDK, `cargo-wdk`, WSL/e2fsprogs, and WSL root loop-mount authority | Runs the development and interoperability gates, builds and signs one identity-bound package, and verifies release reachability. |
| `cargo xtask check-hosted-driver-host` | Elevated Windows host with `TESTSIGNING`, PnPUtil, SCM, and no existing ext4win package/service | Performs the read-only preflight for a kernel-load smoke session. |
| `cargo xtask verify-hosted-driver-load` | A host that passes the hosted preflight and trusts the production signer in LocalMachine Root and Trusted Publishers | Builds one verified production bundle, installs that exact package, completes demand-start driver initialization, and requires service/package cleanup. |
| `cargo xtask cleanup-driver-load-session <session-id>` | Elevated Windows host | Reconciles an interrupted service/package session only after its durable bundle, signer, and package identities match. |
| `cargo xtask check-live-driver-host` | Dedicated host that passes the hosted preflight and also provides Hyper-V PowerShell, WSL/e2fsprogs, and configured Driver Verifier | Performs the read-only preflight for disposable live VHDX validation. |
| `cargo xtask verify-live-vhdx` | A host that passes the live preflight | Builds a verified bundle and exercises it only against a newly created disposable VHDX. |
| `cargo xtask cleanup-live-vhdx-session <session-id>` | Dedicated elevated Windows host | Reconciles an interrupted session and removes only resources whose recorded identities still match. |

`verify-fuzz-replay` is the deterministic pull-request gate for previously retained inputs.
The scheduled fuzz campaign remains a separate, time-bounded search rather than part of the
signed production umbrella.

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

`verify-production-driver` is the signed-bundle and reachability gate. It first runs
`verify-portable`, `verify-driver`, `verify-journal-interop`, and
`verify-htree-interop`. It then creates one build identity, builds and signs the
package, binds the LLVM IR, link map, and driver image to that identity, runs
the production reachability gate, and rejects concurrent source changes. It
fails explicitly on macOS and Linux instead of compiling a non-Windows driver
shim.

Successful bundles are atomically published below
`target/verified-production/<artifact-id>/`. The versioned manifest binds the
IR, MAP, SYS, CAT, and INF hashes to the exact source snapshot, target, profile,
rustflags, and rustc, LLVM, Cargo, `cargo-wdk`, and WDK versions. The production
command neither reuses portable artifacts nor accepts stale release output.

`verify-hosted-driver-load` is the higher CI umbrella. It performs the hosted
preflight, invokes `verify-production-driver`'s bundle construction exactly
once, shuts down the production gate's WSL oracle so its ext4 virtual disk is
not an incidental mount target, and passes the resulting verified bundle value
directly to the DriverStore/service lifecycle owner. The lower production
command remains available when signed artifact and reachability evidence are
the intended boundary without a live kernel-load claim.

## CI and live-driver boundaries

CI runs `verify-portable` on Windows, Ubuntu, and macOS, replays every tracked fuzz corpus on
pull requests, runs time-bounded fuzz campaigns on schedule, and runs ext4 interoperability on
Ubuntu. The blocking driver job runs on the `windows-2025-vs2026` GitHub-hosted
image. It imports the single cargo-wdk certificate identity into LocalMachine
Root and Trusted Publishers, confirms both thumbprints, and then runs
`verify-hosted-driver-load`.

A green production bundle proves signed artifact identity and release
reachability. The hosted load gate additionally proves that structured PnPUtil
inventory selected the sole installed package, both its exported SYS and the
service `ImagePath` SYS match the production manifest SHA-256, the registry
records `Type=2` and `Start=3`, and demand-start initialization returned with
the service in `Running` state. Stop, OEM package removal, and final
service/package absence are mandatory.

The hosted gate does not claim a byte hash of kernel memory, VHDX or filesystem
I/O behavior, or Driver Verifier coverage. Those are distinct live-validation
boundaries and a hosted smoke result does not substitute for them.

`verify-live-vhdx` composes the common driver-load preflight with its additional
Hyper-V, WSL/e2fsprogs, and Driver Verifier requirements. It does not accept a disk path or disk number. It creates one
fixed-size VHDX below `target/live-vhdx-sessions/<session-id>/`, bounds WSL
device discovery to the device introduced by that VHDX, and unmounts the device
from WSL before Windows-driver access. Driver installation, start, stop, package
selection, hash verification, and cleanup are delegated to the same durable
driver-load session used by the hosted gate.

The live scenario requires file create, read, write, rename, hard link,
patterned enumeration, durable flush, clean dismount, driver unload, package
removal, and VHDX removal to succeed. Lifecycle side effects are preceded by a
durably flushed phase manifest. Cleanup revalidates the verified bundle
identity, signer thumbprint, SYS hash, OEM INF, service image path, VHDX path,
and disk unique ID before acting. Physical disks remain permanently outside
this workflow.

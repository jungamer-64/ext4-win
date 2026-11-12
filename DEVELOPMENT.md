# Development

The workspace separates the portable ext4 domain from the Windows kernel
boundary. Default Cargo commands select the host-independent members recorded
in `Cargo.toml`. Use the repository tasks below instead of substituting generic
Cargo commands for a canonical gate.

## Verification commands

| Command | Host requirements | What it establishes |
| --- | --- | --- |
| `cargo xtask verify-portable` | Windows, Linux, or macOS; network access to fetch every locked dependency source (WDK not required) | Checks formatting and all portable targets, runs the portable tests and Clippy, and documents the shared ownership and host boundaries. |
| `cargo xtask verify-windows-host` | Elevated Windows host | Exercises native Windows ETW and token/privilege contracts without installing a driver. |
| `cargo xtask verify-driver` | Windows with MSVC, WDK, and Clang configured | Checks, tests, lints, and documents the kernel-driver crate and its native boundaries. |
| `cargo xtask verify-fuzz-replay` | Pinned cargo-fuzz; Windows also requires MSVC AddressSanitizer libraries and Clang compiler-rt | Checks the locked fuzz dependencies and independent seed acceptance, then replays every target's tracked and generated corpus under the bounded harness. |
| `cargo xtask fuzz` | Same requirements as fuzz replay | Runs each discovered target for a bounded mutation campaign and retains discoveries under `target/fuzz-corpus`. |
| `cargo xtask verify-journal-interop` | Native Linux or Windows with WSL; e2fsprogs | Exercises ext4 mutation and recovery against independently generated `debugfs` and `e2fsck` evidence. |
| `cargo xtask verify-ro-interop` | Native Linux or Windows with WSL; e2fsprogs and Linux root loop-mount authority | Compares RO acceptance, recovery state, orphan cleanup and file observations with native Linux mounts of disposable image copies. |
| `cargo xtask verify-htree-interop` | Native Linux or Windows with WSL; e2fsprogs and root loop-mount authority | Exercises bounded HTree lookup, paging, and local mutation against independently generated ext4 images. |
| `cargo xtask verify-journal-fixture-provenance` | Native Linux or Windows with WSL; root loop-device authority and the manifest-pinned e2fsprogs release | Regenerates the tracked external-journal fixtures and requires byte-for-byte and digest equality. |
| `cargo xtask verify-production-driver` | Windows with MSVC, WDK, `cargo-wdk`, WSL/e2fsprogs, and WSL root loop-mount authority | Runs the development and interoperability gates, builds and signs one identity-bound package, and verifies release reachability. |
| `cargo xtask check-hosted-driver-host` | Elevated Windows host with `TESTSIGNING`, PnPUtil, SCM, and no existing ext4win package/service | Performs the read-only preflight for a kernel-load smoke session. |
| `cargo xtask verify-hosted-driver-load` | A host that passes the hosted preflight and trusts the production signer in LocalMachine Root and Trusted Publishers | Builds one verified production bundle, installs that exact package, completes demand-start driver initialization, and requires service/package cleanup. |
| `cargo xtask cleanup-driver-load-session <session-id>` | Elevated Windows host | Reconciles an interrupted service/package session only after its durable bundle, signer, and package identities match. |
| `cargo xtask check-live-driver-host` | Dedicated host that passes the hosted preflight and also provides Hyper-V PowerShell, WSL/e2fsprogs, and Driver Verifier | Performs the read-only preflight for disposable live VHDX validation. |
| `cargo xtask prepare-live-vhdx <session-id>` | A host that passes the live preflight; a fresh 32-digit lowercase hexadecimal session ID | Builds one verified bundle, creates disposable ext4 storage and binds its installed service in the stopped state. |
| `cargo xtask verify-live-vhdx <session-id>` | The same host with a successfully prepared session, unchanged source inputs, and English Windows runtime output | Revalidates the exact prepared installation, activates it and exercises startup discovery, native I/O and remount before required cleanup. |
| `cargo xtask benchmark-multi-file` | A host that passes the live preflight | Measures native random reads and writes on independently populated disposable storage, retaining artifact-bound latency and flush evidence. |
| `cargo xtask cleanup-live-vhdx-session <session-id>` | Dedicated elevated Windows host | Reconciles an interrupted session and removes only resources whose recorded identities still match. |

The [development tasks](tools/xtask/src/development.rs) define the format, lint,
test, and rustdoc gates. CI hosts and triggers are defined in the
[verification workflow](.github/workflows/verify.yml) and
[fuzz workflow](.github/workflows/fuzz.yml).

The core's [build script](crates/ext4-core/build.rs) generates its Unicode runtime
table and the verbatim Unicode data notice in Cargo's `OUT_DIR` using the
[generator](tools/unicode-gen/src/lib.rs), which owns the fixed encoding version and
authenticated upstream inputs. Neither UCD inputs nor generated output belong in the
source tree. A cache miss requires an HTTPS-capable `curl` executable on `PATH`.
Inputs are cached in `ext4-win-ucd-<version>` under the host temporary directory;
`EXT4_UCD_CACHE` selects an absolute external cache path. Cargo's `--offline` controls
only dependency resolution, so offline generation and packaging need every UCD input
and the notice in that cache. A hash mismatch fails the build; remove the named cache
file to permit a fresh download.

## Developer diagnostics

`cargo diagnose` runs the Rust diagnostic executable. Inputs are explicit;
results are JSON on stdout and failures return a nonzero exit status.

```console
cargo diagnose host
cargo diagnose service --name ext4win
cargo diagnose volume C:/
cargo diagnose stack target/verified-production/<artifact-id> --limit 20 --rva 0x1234
cargo diagnose completion target/verified-production/<artifact-id>
cargo diagnose extent --superblock superblock.bin --block extent.bin --inode 8 --generation 0
cargo diagnose waits kernel.log --match ext4win! --encoding utf-8
```

Artifact diagnostics validate the requested bundle's manifest hashes and analyze
that snapshot. They do not establish that the bundle matches the current checkout,
is trusted, or is loaded; rebuild with `verify-production-driver` when current-source
evidence is required. Stack and completion inspection are bounded static analyses,
not live stack bounds or runtime behavior.

`service` and `volume` require Windows and change neither driver lifecycle nor
storage. Volume queries can block inside the filesystem driver; the tool does not
cancel a pending kernel operation.

## Volume control operations

`ext4ctl` uses the secured control endpoint, which accepts only Administrators and
SYSTEM; run it from an elevated shell. Durable control replacements report an outcome
phase. A communication failure or cancellation is not evidence that the operation had
no effect, and the CLI never retries an unacknowledged mutation automatically. Query or
observe the target before deciding on another mutation.

### Identity mapping

```console
cargo run -p ext4ctl -- volumes
cargo run -p ext4ctl -- whoami
cargo run -p ext4ctl -- identity show <volume-path-or-ext4-uuid>
cargo run -p ext4ctl -- identity replace <volume-path-or-ext4-uuid> --user <account-or-SID> <UID> --group <account-or-SID> <GID>
cargo run -p ext4ctl -- identity clear <volume-path-or-ext4-uuid>
```

UID and GID values are explicit filesystem identities, with no UID 0 bypass. Repeat
`--user` and `--group` for additional principals. Replacement contains the entire table;
clear durably replaces it with an empty table. Both SID and numeric ID must be unique
within each identity domain. Synthetic UNIX SIDs identify otherwise unmapped inode
metadata and cannot alias another configured numeric identity. New inode creation
requires explicit mappings for both effective token principals. New files use creation
mode 0644 and directories 0755.

Configuration is keyed by ext4 UUID, shared by mounts of that UUID, and stored as the
`Table` REG_BINARY value under the service's `Parameters\IdentityMappings\<UUID>` key.
Invalid saved records prevent driver initialization. Replacement affects subsequent
operations; existing handles retain their previously granted rights.

`show` reports saved and applied generations, the last native status, and the commit
phase. Replacement requires the observed generation. NotSaved means no table effect was
accepted; SavedNotApplied is a durable successor awaiting publication; Unknown requires
query reconciliation, which reads and flushes uncertain storage before publishing a
validated result.

Windows access is a projection of POSIX ownership, mode and ACLs. POSIX rwx does not
grant DELETE, so applications requesting it can receive access denied. Maximum-access
queries do not implicitly explore WRITE_OWNER, ACCESS_SYSTEM_SECURITY or namespace
deletion; explicit ownership and security privilege requests are checked by Windows.
Backup-intent opens evaluate enabled backup and restore privileges; ordinary opens do
not receive these grants. Without traversal-bypass privilege, recursive directory
watches return a descendant name only when every crossed directory grants
`FILE_TRAVERSE` to the watcher. Security mutations accept owner/group changes and the
mode projection; an inode with an access ACL accepts only an unchanged projected DACL,
and arbitrary Windows ACL edits are rejected.

### Mounted-session policy

```console
cargo run -p ext4ctl -- policy show <volume-path-or-ext4-uuid>
cargo run -p ext4ctl -- policy set <volume-path-or-ext4-uuid> --access read-only
cargo run -p ext4ctl -- policy set <volume-path-or-ext4-uuid> --access read-only --recovery noload
cargo run -p ext4ctl -- policy set <volume-path-or-ext4-uuid> --access read-only --recovery memory --recovery-memory 67108864
cargo run -p ext4ctl -- policy set <volume-path-or-ext4-uuid> --access read-write
```

Saving policy requires a matching predecessor generation. Each mount selects one durable
snapshot before recovery; saving policy does not remount a volume or switch an existing
session between read-only and read-write. The service's
`Parameters\MountPolicies\<UUID>\Table` binary value stores one complete policy, and the
shared [control codec](crates/ext4-control/src/lib.rs) owns its wire layout and defaults.
An Unknown outcome must be reconciled by query before another replacement or mount
selection can proceed.

`--access read-only` selects ordinary journal replay; `--recovery replay` selects it
explicitly. Required recovery writes reach media before read-only publication, so
write-protected media cannot admit required journal recovery. Standard RO requires a
valid primary checksum and does not claim or inspect MMP ownership. `noload` skips
journal loading, including external-journal discovery; it does not suppress
independently admitted orphan cleanup, which requires writable media and no recorded
filesystem error and then uses home writes without a journal.

`memory` selects private recovery and bounded primary-checksum rescue through
authenticated journal replay. It issues no lower media write or flush, including at
close. Recovery memory is a nonzero logical byte budget; exhaustion is distinct from
physical allocation failure. A budget alone does not select this mode. Unspecified access
retains its observed value; an access-only RO update selects replay. Budgets can be
changed only while selecting or retaining memory recovery, and saving RW with recovery
options is rejected. Failed recovery reports whether media was unchanged, partially
updated or has an uncertain effect; it is not retried or switched to another mode.

### Directory comparison

```console
cargo run -p ext4ctl -- casefold show <directory>
cargo run -p ext4ctl -- casefold set <directory> on
cargo run -p ext4ctl -- casefold set <directory> off
```

Changing comparison requires attribute-write access to the directory handle, a filesystem
with a declared casefold encoding, and an empty directory.

### Declared filesystem features

```console
cargo run -p ext4ctl -- features <volume-path>
```

The observation contains the filesystem UUID, the complete compatible, incompatible and
read-only-compatible masks, and the media access admitted before recovery. Named entries
describe on-disk declarations, not current mutation permission; an independent ownership
or reliability failure can prevent writes after writable mount admission. Memory recovery
reports its committed private metadata view; noload observes home metadata.

### Free-space discard

```console
cargo run -p ext4ctl -- trim <volume-path-or-ext4-uuid>
```

The mounted volume must be writable, and the requester's SeManageVolumePrivilege authorizes
the scan. The reply retains acknowledged bytes and the bytes in a batch whose result is
uncertain. Cancellation, unsupported discard and lower errors stop the scan without
resubmission. A UUID target is resolved on each invocation; an unmounted UUID or multiple
mounted copies of that UUID fail before discard.

Periodic TRIM belongs to Windows Task Scheduler; mounted-session policy contains no
scheduling state. Build `ext4ctl` with `cargo build --release --package ext4ctl` and install
the executable in a stable directory writable only by administrators and SYSTEM. From an
elevated PowerShell session, use the [task registration script](tools/ext4ctl/trim-schedule.ps1)
with the UUID reported by `ext4ctl volumes`:

```powershell
.\tools\ext4ctl\trim-schedule.ps1 -Action Register -FilesystemUuid <ext4-uuid> -Executable <installed-ext4ctl.exe>
.\tools\ext4ctl\trim-schedule.ps1 -Action Show -FilesystemUuid <ext4-uuid>
.\tools\ext4ctl\trim-schedule.ps1 -Action Remove -FilesystemUuid <ext4-uuid>
```

Registration creates `ext4win-TRIM-<ext4-uuid>` without replacing an existing task or
starting it; `-Action Export` returns the task XML without registration. The script defines
the default weekly trigger and task settings; later cadence changes and execution history
belong to Task Scheduler. Each invocation runs one `ext4ctl trim <ext4-uuid>` as SYSTEM and
starts a fresh metadata scan; it never resumes an uncertain batch. Removing a task prevents
future starts and lets an existing scan finish.

## Ext4 durability and interoperability

Interoperability uses e2fsprogs as an independent oracle on newly formatted or
freshly copied images. Linux-local fixture mutations run an executable built
from current source, including when invoked through WSL. Tested profiles and
operations are defined by the [interoperability scenarios](tools/xtask/src/interop/scenarios.rs)
and [orphan recovery cases](tools/xtask/src/interop/scenarios/orphan.rs).

External-journal crash recovery is accepted only when `e2fsck -f` is clean and
the observable namespace, content, links, xattrs, and allocation state are
wholly old or wholly new before commit durability. After the commit's journal
flush succeeds, recovery must retain the complete new state, including when
the flush acknowledgement is lost. Interrupted orphan recovery must checkpoint tracker
cleanup before remount publication; clean close must leave an `e2fsck`-clean
allocation and namespace endpoint.

The crash model assumes atomic 512-byte sectors. Writes may be absent, may
persist at a sector-aligned prefix, or may persist completely. Unflushed write
completion does not impose persistence order. The bounded matrix tests each
write prefix both in isolation and with the other pending writes retained;
it does not enumerate all pending-write subsets. Successful flushes make all
earlier writes durable only on the target device. Pending writes on the other
device remain independently selectable after that flush.

Volume feature, geometry, and journal acceptance are determined by
[core mount validation](crates/ext4-core/src/volume/mount.rs).

## Production release evidence

`verify-production-driver` builds and signs one bundle from a fixed source
snapshot, rejects concurrent source changes, and verifies release reachability.
The [production workflow](tools/xtask/src/production.rs) defines the composed gates,
artifact checks and manifest bindings; the
[reachability gate](tools/production-reachability/src/main.rs) defines the
allocation-free durable-publication audit and required native boundaries.
Linked entry points do not establish live behavior.

Successful bundles are atomically published below
`target/verified-production/<artifact-id>/`, with a manifest binding the produced
artifacts to the exact source snapshot and toolchain. The production command neither
reuses portable artifacts nor accepts stale release output.

Each bundle carries verbatim license and copyright documents for the driver's
target-resolved normal dependency closure and the Rust standard library, bound by
SHA-256 in the manifest; missing source notices prevent publication. `LICENSE-MIT` and
`LICENSE-APACHE` at the repository root are the authoritative project texts carried by
production bundles. The core and driver crates are internal workspace components and
are not published separately.

## Live-driver validation and recovery

`verify-hosted-driver-load` establishes package and configured-image identity and
successful demand-start initialization, not a hash of kernel memory or filesystem I/O
behavior. The verification workflow's initialization-only scenario likewise does not
establish volume discovery, mount or filesystem I/O behavior.

Successful preparation retains the attached VHDX and stopped installation until
verification or explicit session cleanup completes; it does not establish kernel
execution. Initial activation consumes the prepared session's permission before SCM
start, so an interrupted start requires reconciliation rather than repeating activation.
Artifact bytes, signer trust, service configuration, storage scope and source identity
are revalidated before start. Cleanup remains possible after source changes.

`verify-live-vhdx` additionally requires persisted Windows readback after flush,
dismount, and VHDX reattachment with the same loaded driver, and runtime Driver
Verifier evidence identifying active checks and the loaded driver before and after
filesystem I/O. Unknown Verifier report formats fail validation. Live results apply to
the generated volume and exercised scenarios, not arbitrary physical volumes or untested
feature combinations. Disk offline/online cycles must preserve the volume GUID and drive
letters. The [live-session owner](tools/xtask/src/live/owner.rs) defines
scenario execution and evidence collection.

Live evaluation creates its own VHDX below `target/live-vhdx-sessions/<session-id>/` and
accepts no disk path or disk number. WSL access is confined to that VHDX and WSL is shut
down before driver startup, so its own ext4 disk cannot become a discovery target. Load
preflight rejects existing Linux data GUID volumes; immediately before driver startup,
any such partition must match the session's generated VHDX, disk identity and exact
partition identity/range. The dedicated host must remain free of unrelated storage
arrivals throughout the run. [Partition admission](crates/ext4-driver/src/kernel/volume_discovery.rs)
and [volume publication](crates/ext4-driver/src/kernel/device_interface.rs) own the
recognition contracts.

Lifecycle effects are preceded by durably flushed session intent records; an intent does
not establish completion. After interruption, use the matching cleanup command from the
command table. The [driver-load owner](tools/xtask/src/driver_load/owner.rs) and
[session records](tools/xtask/src/session.rs) define recovery and persistence.
A start timeout leaves the service and package in place while SCM reports `StartPending`.
Prepare-unload can return busy while lower I/O remains outstanding. Cancellation or an
absent control endpoint is not proof of unload: SCM stop, package removal, and final
service/package absence are required.

Operational ETW carries no file names, offsets, lengths, pointers, or file data; its
[provider owner](crates/ext4-driver/src/kernel/operational_trace.rs) defines the payload.
Delivery is buffered, so missing final events do not establish that an operation never
started.

Live validation requires filesystem validation, driver unload, and service, package, and
VHDX cleanup. Available evidence is retained after failure and recovery is attempted;
cleanup cannot turn failed I/O into a passing result. A VM crash or job timeout can
prevent cleanup and evidence upload, and that run is not acceptance evidence.

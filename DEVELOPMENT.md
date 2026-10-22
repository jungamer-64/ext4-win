# Development

The workspace separates the portable ext4 domain from the Windows kernel
boundary. Default Cargo commands select the host-independent members recorded
in `Cargo.toml`. Use the repository tasks
below instead of substituting generic Cargo commands for a canonical gate.

`verify-portable` fetches the locked workspace dependency sources before running
tests. The source-notice sealing test reads the Windows driver's dependency
closure offline even on a non-Windows host; fetching those sources does not
compile the driver or require WDK.

## Verification commands

| Command | Host requirements | What it establishes |
| --- | --- | --- |
| `cargo xtask verify-portable` | Windows, Linux, or macOS | Checks formatting and all portable targets, runs the portable tests and Clippy, and documents the host boundary. |
| `cargo xtask verify-windows-host` | Elevated Windows host | Exercises native Windows ETW and token/privilege contracts without installing a driver. |
| `cargo xtask verify-driver` | Windows with MSVC, WDK, and Clang configured | Checks, tests, lints, and documents the kernel-driver crate and its native boundaries. |
| `cargo xtask verify-fuzz-replay` | Host with the repository-pinned cargo-fuzz installed | Discovers every declared fuzz target and replays its tracked corpus once under the bounded fuzz harness. |
| `cargo xtask verify-journal-interop` | Native Linux or Windows with WSL; e2fsprogs | Exercises ext4 mutation and recovery against independently generated `debugfs` and `e2fsck` evidence. |
| `cargo xtask verify-htree-interop` | Native Linux or Windows with WSL; e2fsprogs and root loop-mount authority | Exercises bounded HTree lookup, paging, and local mutation against independently generated ext4 images. |
| `cargo xtask verify-journal-fixture-provenance` | Native Linux or Windows with WSL; root loop-device authority and the manifest-pinned e2fsprogs release | Regenerates the tracked external-journal fixtures and requires byte-for-byte and digest equality. |
| `cargo xtask verify-production-driver` | Windows with MSVC, WDK, `cargo-wdk`, WSL/e2fsprogs, and WSL root loop-mount authority | Runs the development and interoperability gates, builds and signs one identity-bound package, and verifies release reachability. |
| `cargo xtask check-hosted-driver-host` | Elevated Windows host with `TESTSIGNING`, PnPUtil, SCM, and no existing ext4win package/service | Performs the read-only preflight for a kernel-load smoke session. |
| `cargo xtask verify-hosted-driver-load` | A host that passes the hosted preflight and trusts the production signer in LocalMachine Root and Trusted Publishers | Builds one verified production bundle, installs that exact package, completes demand-start driver initialization, and requires service/package cleanup. |
| `cargo xtask cleanup-driver-load-session <session-id>` | Elevated Windows host | Reconciles an interrupted service/package session only after its durable bundle, signer, and package identities match. |
| `cargo xtask check-live-driver-host` | Dedicated host that passes the hosted preflight and also provides Hyper-V PowerShell, WSL/e2fsprogs, and Driver Verifier | Performs the read-only preflight for disposable live VHDX validation. |
| `cargo xtask verify-live-vhdx` | A host that passes the live preflight | Builds a verified bundle and exercises it only against a newly created disposable VHDX. |
| `cargo xtask benchmark-multi-file` | A host that passes the live preflight | Measures native random reads and writes on independently populated disposable storage, retaining artifact-bound latency and flush evidence. |
| `cargo xtask cleanup-live-vhdx-session <session-id>` | Dedicated elevated Windows host | Reconciles an interrupted session and removes only resources whose recorded identities still match. |

The [development tasks](tools/xtask/src/development.rs) define the format, lint,
test, and rustdoc gates. CI hosts and triggers are defined in the
[verification workflow](.github/workflows/verify.yml) and
[fuzz workflow](.github/workflows/fuzz.yml).

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
the bytes read into that snapshot. They do not establish that the bundle matches
the current checkout, is trusted, or is loaded. Rebuild with
`verify-production-driver` when current-source evidence is required. Stack
inspection reports fixed AMD64 prolog frames, not a complete call-chain or live
stack bound. Completion inspection rejects unmodeled IR forms and checks context
capture, marker installation and immediate restoration around direct native
completion calls, rejecting paths that can reenter completion without capture.
Aliases, indirect calls and runtime Filter Manager behavior
are outside that analysis.

`service` and `volume` require Windows. Service hashing requires an explicit
driver `ImagePath` and identifies that configured image on disk. Volume queries
can block inside the filesystem driver; the tool does not claim to cancel a
pending kernel operation. Neither command changes
driver lifecycle or storage. Extent input files must be a complete superblock
and external extent block; the checksum result does not validate the rest of
the filesystem. Wait-log extraction reports its match count and any truncation.

## Volume identity administration

`cargo run -p ext4ctl -- volumes` lists mounted ext4 UUIDs and Windows volume paths.
`whoami` reports the effective token's user and primary-group SIDs, including thread impersonation.
The secured control endpoint accepts only Administrators and SYSTEM; run identity administration
from an elevated shell. UID and GID values are explicit filesystem identities, with no UID 0 bypass.

```console
cargo run -p ext4ctl -- whoami
cargo run -p ext4ctl -- identity show <volume-path-or-ext4-uuid>
cargo run -p ext4ctl -- identity replace <volume-path-or-ext4-uuid> --user <account-or-SID> <UID> --group <account-or-SID> <GID>
cargo run -p ext4ctl -- identity clear <volume-path-or-ext4-uuid>
```

Repeat `--user` and `--group` for additional principals. Replacement contains the entire table;
clear durably replaces it with an empty table. Both SID and numeric ID must be unique within each
identity domain. Synthetic UNIX SIDs identify otherwise unmapped inode metadata and cannot alias
another configured numeric identity. New inode creation requires explicit mappings for both
effective token principals; existing inodes use their access ACL, or owner/group/other mode when
no access ACL is stored. Named user/group entries are constrained by the ACL mask. Inode rwx
fields and access ACL base classes must agree; chmod updates the corresponding ACL entries.
New files use 0644 and directories 0755. Parent setgid selects the inherited GID and propagates
setgid to child directories. A parent default ACL supplies the child access ACL, restricted
by its creation mode, and propagates unchanged as the default ACL of child directories.

Configuration is keyed by ext4 UUID, shared by mounts of that UUID, and stored as the `Table`
REG_BINARY value under the service's `Parameters\IdentityMappings\<UUID>` key. The driver validates
saved tables before mount publication. Invalid saved records prevent driver initialization.
Each open, traversal, security query or security mutation pins one table. Replacement affects
subsequent operations; existing handles retain their previously granted rights. Data read/write
uses that retained authority without reading the table or registry.

`show` reports saved and applied generations, the last native status, and the commit phase.
Replacement checks the observed generation, prepares storage, saves and flushes the whole value,
then publishes the UUID's successor. NotSaved means no table effect was accepted;
SavedNotApplied distinguishes a durable successor awaiting publication; Unknown requires query
reconciliation. A query reads and flushes uncertain storage before publishing a validated result.
A communication failure or cancellation is not evidence that replacement failed to persist.
Query first and inspect the complete table and generations before deciding on another replacement.
The CLI does not automatically retry an unacknowledged write or a generation conflict.

POSIX access policy controls data, EA and mutable attribute rights through specific-right ACEs.
Owner and named-user matches take precedence over group membership and other permissions.
A composite rwx request requires one matching group entry to supply the whole combination. Read attributes,
READ_CONTROL and SYNCHRONIZE are common base rights. Maximum access checks individual rights with
the same native subject, excluding implicit exploration of WRITE_OWNER, ACCESS_SYSTEM_SECURITY
and namespace deletion. Explicit ownership/security privilege requests are checked by Windows.
POSIX rwx does not grant DELETE; applications requesting it can receive access denied.
Backup-intent opens evaluate enabled backup and restore privileges before remaining descriptor
rights, and record privilege use before publishing handle authority. Ordinary opens do not
receive these privilege grants.
Security queries support variable SID lengths and report the required size for short buffers.
Security mutations accept the owner/group/mode projection for inodes without an access ACL.
An inode with an access ACL accepts owner/group updates and an unchanged projected DACL;
arbitrary Windows ACL edits are rejected. Mode changes through file attributes update its ACL mask.
Native token oracles run in portable Windows tests; the elevated `verify-windows-host` gate also
checks explicit ownership and security privileges.

## Ext4 durability and interoperability

Interoperability uses e2fsprogs as an independent oracle on newly formatted or
freshly copied images. Linux-local fixture mutations run an executable built
from current source, including when invoked through WSL. Tested profiles and
operations are defined by the [interoperability scenarios](tools/xtask/src/interop/scenarios.rs)
and [orphan recovery cases](tools/xtask/src/interop/scenarios/orphan.rs).

External-journal crash recovery is accepted only when `e2fsck -f` is clean and
the observable namespace, content, links, xattrs, and allocation state are
wholly old or wholly new. Interrupted orphan recovery must checkpoint tracker
cleanup before remount publication; clean close must leave an `e2fsck`-clean
allocation and namespace endpoint.

The crash model assumes atomic 512-byte sectors. Writes may be absent, may
persist at a sector-aligned prefix, or may persist completely. Successful
flushes preserve prior write ordering and make durable only the target device,
so an external journal and its filesystem image have independent volatile and
durable states.

Volume feature, geometry, and journal acceptance are determined by
[core mount validation](crates/ext4-core/src/volume/mount.rs).

## Production release evidence

`verify-production-driver` builds and signs one bundle from a fixed source
snapshot and verifies release reachability. It rejects concurrent source
changes. The [production workflow](tools/xtask/src/production.rs) defines the
composed gates and artifact checks; the
[reachability gate](tools/production-reachability/src/main.rs) defines the
allocation-free durable-publication audit and required native boundaries.
Linked entry points do not establish live behavior.

Successful bundles are atomically published below
`target/verified-production/<artifact-id>/`. The versioned manifest binds the
IR, MAP, SYS, CAT, and INF hashes to the exact source snapshot, target, profile,
rustflags, and rustc, LLVM, Cargo, `cargo-wdk`, and WDK versions. The production
command neither reuses portable artifacts nor accepts stale release output.

Each bundle also carries verbatim license and copyright documents for the
driver's target-resolved normal dependency closure and the Rust standard
library. The package index identifies each source and its declared license;
the production manifest binds every copied document by SHA-256. Missing source
notices prevent publication. `LICENSE-MIT` and `LICENSE-APACHE` at the repository
root are the authoritative project texts. The core and driver crates are internal
workspace components and are not published separately. Production bundles carry
the project's original license texts from the repository root.

## Live-driver validation and recovery

`verify-hosted-driver-load` installs the verified bundle and checks that the
DriverStore and service images match its SHA-256, then requires demand-start
initialization and complete service/package cleanup. This establishes package
and configured-image identity and successful initialization, not a hash of
kernel memory or filesystem I/O behavior.

`verify-live-vhdx` additionally requires persisted Windows readback after flush,
dismount, and VHDX reattachment with the same loaded driver. Runtime Driver
Verifier evidence must identify active checks and the loaded driver before and
after filesystem I/O. The report parser requires English Windows runtime
output; unknown formats fail validation. Live results apply to the generated
volume and exercised scenarios, not arbitrary physical volumes or untested
feature combinations. The [live-session owner](tools/xtask/src/live/owner.rs)
defines scenario execution and evidence collection.

Live evaluation requires a dedicated, elevated Windows host and creates its own
VHDX below `target/live-vhdx-sessions/<session-id>/`. It accepts no disk path or
disk number. WSL access is confined to that VHDX and ends before Windows-driver
access; WSL is shut down before driver startup so its own ext4 disk cannot
become a discovery target.

Load preflight rejects existing Linux data GUID volumes. Immediately before
driver startup, any such partition must match the live session's generated VHDX,
disk identity and exact partition identity/range. The dedicated host must remain
free of unrelated storage arrivals throughout the run.

The disposable partition retains its Linux filesystem data type, identity, and
range. Mount Manager must enumerate that exact disk extent before a
session-owned directory mount point is created. Discovery is checked at driver
startup and reattachment; [partition admission](crates/ext4-driver/src/kernel/volume_discovery.rs)
and [volume publication](crates/ext4-driver/src/kernel/device_interface.rs) own the
recognition contracts.

Recognized volumes expose the standard volume interface on their existing storage
PDO. PnP removal withdraws active Mount Manager links while preserving persistent
volume identity and mount-point assignments for reattachment. Live validation
requires the same volume GUID and drive letters after disk offline/online cycles.

Lifecycle effects are preceded by durably flushed session intent records. An
intent does not establish completion. After interruption, use the matching
cleanup command from the command table; recovery reloads the committed record
and revalidates artifact, signer, package, service, and storage identities
before acting. Volume state is reconciled and mounted storage is cleanly
dismounted before detachment or driver retirement. The
[driver-load owner](tools/xtask/src/driver_load/owner.rs) and
[session records](tools/xtask/src/session.rs) define recovery and persistence.

A start timeout does not cancel DriverEntry; recovery retains the service and
package while SCM reports `StartPending`. Prepare-unload can return busy while
lower I/O remains outstanding. Cancellation or an absent control endpoint is
not proof of unload: SCM stop, package removal, and final service/package
absence are required. The driver retains outstanding resources according to
its [discovery exchange](crates/ext4-driver/src/kernel/volume_discovery/io.rs)
and [device retirement](crates/ext4-driver/src/state/control_device.rs) contracts.

Operational ETW carries fixed event IDs, status, and outcomes without file
names, offsets, lengths, pointers, or file data; its
[provider owner](crates/ext4-driver/src/kernel/operational_trace.rs) defines the
payload and registration lifetime. Delivery is buffered, so missing final
events do not establish that an operation never started.

Live validation requires filesystem validation, driver unload, and service,
package, and VHDX cleanup. Available evidence is retained after failure and recovery is
attempted; cleanup cannot turn failed I/O into a passing result. A VM crash or
job timeout can prevent cleanup and evidence upload, and that run is not
acceptance evidence.

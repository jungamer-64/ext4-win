//! Production-root reachability gate for the release driver LLVM IR.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet, TryReserveError, VecDeque},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::fmt;
use std::{env, fs, io, path::PathBuf, process::ExitCode};

/// The exported driver entry point.
const DRIVER_ENTRY: &str = "DriverEntry";

/// The only production function permitted to invoke `KeBugCheckEx`.
const FATAL_BUGCHECK_ALLOWLIST: &[&str] =
    &["<ext4win::kernel::fatal::KernelWideInconsistency>::bugcheck"];

/// Release boundary whose complete reachable graph must remain allocation-free after durability.
const DURABLE_PUBLISH_ROOT: &str = "<ext4win::state::volume::MountedVolumeAccess>::publish_durable";

/// Required active top-level IRP cancellation callback.
const ACTIVE_CANCEL_CALLBACK: &str = "ext4win::irp::cancel::active_irp_cancelled";

/// Required fixed-slot storage retry timer callback.
const STORAGE_RETRY_CALLBACK: &str = "ext4win::irp::reactor::storage_retry_timer_dpc";

/// Prefix retained in both the audited LLVM IR and linked PE image.
const ARTIFACT_ID_MARKER: &str = "EXT4WIN_ARTIFACT_ID=";

/// Entire marker record length: the fixed prefix followed by 32 hexadecimal digits.
const ARTIFACT_ID_RECORD_LENGTH: usize = 52;

/// Sentinel emitted for developer builds that are not production artifact bundles.
const UNVERIFIED_ARTIFACT_ID: &str = "00000000000000000000000000000000";

/// Linker symbol forcing the artifact marker into the final image.
const ARTIFACT_ID_SYMBOL: &str = "EXT4WIN_PRODUCTION_ARTIFACT_ID";

/// Linked production roots and protocol boundaries required in the final image map.
const REQUIRED_LINKED_SYMBOLS: &[(&str, &str)] = &[
    ("active cancellation callback", "active_irp_cancelled"),
    ("storage retry timer callback", "storage_retry_timer_dpc"),
    ("lower completion routine", "lower_request_completed"),
    ("durable publication boundary", "publish_durable"),
    ("completion registration import", "IoSetCompletionRoutineEx"),
    ("lower submission import", "IofCallDriver"),
    ("native advanced-header allocation", "ext4win_stream_create"),
    (
        "native stream owner decoding",
        "ext4win_stream_decode_owner",
    ),
    (
        "native section-object identity",
        "ext4win_stream_section_objects",
    ),
    ("native stream size observation", "ext4win_stream_get_sizes"),
    ("native stream size publication", "ext4win_stream_set_sizes"),
    ("native stream destruction", "ext4win_stream_destroy"),
    (
        "cache-map initialization",
        "ext4win_stream_cache_initialize",
    ),
    ("cached read boundary", "ext4win_stream_cache_read"),
    ("cached write boundary", "ext4win_stream_cache_write"),
    ("cache flush boundary", "ext4win_stream_cache_flush"),
    (
        "cache coherency boundary",
        "ext4win_stream_cache_coherency_flush_and_purge",
    ),
    (
        "cache-map finalization",
        "ext4win_stream_cache_uninitialize",
    ),
    ("oplock FSCTL boundary", "ext4win_stream_oplock_fsctrl"),
    ("oplock package delegation", "FsRtlOplockFsctrlEx"),
    ("Fast I/O registration", "ext4win_fast_io_dispatch"),
    ("Fast I/O read callback", "ext4win_fast_io_read"),
    ("Fast I/O write callback", "ext4win_fast_io_write"),
    ("operational ETW registration", "ext4win_trace_register"),
    ("operational ETW event emission", "ext4win_trace_write"),
    ("operational ETW unregister", "ext4win_trace_unregister"),
    ("kernel ETW provider registration", "EtwRegister"),
    ("kernel ETW event enable query", "EtwEventEnabled"),
    ("kernel ETW event write", "EtwWrite"),
    ("kernel ETW provider unregister", "EtwUnregister"),
    (
        "GPT volume identity query",
        "ext4win_query_volume_partition",
    ),
    (
        "hidden volume recognition read",
        "ext4win_read_volume_prefix",
    ),
    (
        "Mount Manager volume publication",
        "ext4win_announce_volume",
    ),
    ("raw-volume operation admission", "raw_volume"),
];

/// AMD64 COFF machine identifier.
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// PE32+ optional-header magic.
const PE32_PLUS_MAGIC: u16 = 0x020b;

/// Native subsystem identifier used by kernel drivers.
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;

/// Minimum PE32+ optional-header size through the certificate directory entry.
const REQUIRED_OPTIONAL_HEADER_SIZE: usize = 152;

/// Current `WIN_CERTIFICATE` revision emitted by Authenticode tooling.
const WIN_CERT_REVISION_2_0: u16 = 0x0200;

/// PKCS#7 signed-data certificate type used by Authenticode.
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// Fixed header bytes preceding a `WIN_CERTIFICATE` payload.
const WIN_CERTIFICATE_HEADER_SIZE: usize = 8;

/// The only legal terminal status for an ext4win-created lower IRP completion routine.
const MORE_PROCESSING_REQUIRED_RETURN: &str = "ret i32 -1073741802";

/// Maximum number of independent violation paths printed by one run.
const MAX_REPORTED_VIOLATIONS: usize = 64;

/// Result type used by the analyzer and its command-line boundary.
type GateResult<T> = Result<T, GateError>;

/// A deterministic analysis or artifact-discovery failure.
#[derive(Debug)]
enum GateError {
    /// A filesystem operation failed.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Path associated with the operation.
        path: PathBuf,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// Memory reservation required by the host-side artifact analysis failed.
    Allocation {
        /// Analyzer structure being reserved.
        purpose: &'static str,
        /// Allocation or capacity failure returned by the collection.
        source: TryReserveError,
    },
    /// The LLVM IR is not structurally usable by the graph gate.
    InvalidIr(String),
    /// The release artifacts do not form one verified production bundle.
    InvalidArtifact(String),
    /// The command-line arguments do not match the gate contract.
    InvalidArguments,
}

impl fmt::Display for GateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::Allocation { purpose, source } => {
                write!(formatter, "cannot allocate {purpose}: {source}")
            }
            Self::InvalidIr(detail) => write!(formatter, "invalid LLVM IR: {detail}"),
            Self::InvalidArtifact(detail) => {
                write!(formatter, "invalid release artifact: {detail}")
            }
            Self::InvalidArguments => write!(
                formatter,
                "usage: production-reachability <release-ext4win.ll> <release-ext4win.map> <signed-ext4win.sys>"
            ),
        }
    }
}

impl core::error::Error for GateError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Allocation { source, .. } => Some(source),
            Self::InvalidIr(_) | Self::InvalidArtifact(_) | Self::InvalidArguments => None,
        }
    }
}

/// A normalized opaque-pointer LLVM function signature.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FunctionSignature {
    /// LLVM return type.
    result: String,
    /// Top-level LLVM argument types.
    parameters: Vec<String>,
    /// Whether the function accepts a variable argument tail.
    variadic: bool,
}

impl fmt::Display for FunctionSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}(", self.result)?;
        let mut separator = "";
        for parameter in &self.parameters {
            write!(formatter, "{separator}{parameter}")?;
            separator = ", ";
        }
        if self.variadic {
            write!(formatter, "{separator}...")?;
        }
        formatter.write_str(")")
    }
}

/// One indirect call site awaiting conservative target expansion.
#[derive(Clone, Debug)]
struct IndirectCall {
    /// Normalized call-site signature.
    signature: FunctionSignature,
    /// One-based LLVM IR line number.
    line: usize,
}

/// A defined or declared LLVM function.
#[derive(Debug)]
struct Function {
    /// Human-readable name recovered from LLVM comments.
    display: String,
    /// Normalized function signature.
    signature: FunctionSignature,
    /// Direct calls and callback-address flows.
    edges: BTreeSet<String>,
    /// Direct call targets in LLVM instruction order.
    direct_calls: Vec<String>,
    /// Normalized body instructions and basic-block labels in source order.
    body: Vec<String>,
    /// Indirect call sites in the function body.
    indirect_calls: Vec<IndirectCall>,
    /// Normalized LLVM return instructions in the function body.
    returns: Vec<String>,
    /// Whether LLVM exposes the definition outside the module.
    externally_visible: bool,
}

/// Parsed production call graph inputs from one LLVM module.
#[derive(Debug)]
struct IrModule {
    /// All function definitions and declarations by LLVM symbol.
    functions: BTreeMap<String, Function>,
    /// Functions used as values rather than direct call targets.
    address_taken: BTreeSet<String>,
    /// Explicit production roots.
    roots: BTreeSet<String>,
}

/// A categorized path from a production root to a forbidden sink.
#[derive(Debug)]
struct Violation {
    /// Stable category printed before the path.
    category: &'static str,
    /// Human-readable root-to-sink path.
    path: Vec<String>,
}

/// Successful graph construction and its reachability findings.
#[derive(Debug)]
struct AnalysisReport {
    /// Number of functions in the LLVM module.
    function_count: usize,
    /// Number of functions reachable from production roots.
    reachable_count: usize,
    /// Number of address-taken targets used for indirect expansion.
    address_taken_count: usize,
    /// Forbidden or unresolved paths.
    violations: Vec<Violation>,
}

/// Explicit paths for one production artifact bundle.
#[derive(Debug)]
struct ArtifactPaths {
    /// Release LLVM IR emitted by the driver compilation.
    ir: PathBuf,
    /// Link map emitted by the same driver compilation.
    link_map: PathBuf,
    /// Signed package driver copied from that link.
    driver: PathBuf,
}

/// Validated one-build identifier retained in compilation and link outputs.
#[derive(Debug, Eq, PartialEq)]
struct ArtifactIdentity(String);

/// Identity-bearing release inputs loaded from disk.
#[derive(Debug)]
struct ArtifactBundle {
    /// Validated paths supplied on the command line.
    paths: ArtifactPaths,
    /// UTF-8 LLVM IR text.
    ir: String,
    /// Parsed final-image link map.
    link_map: LinkMap,
    /// Shared non-sentinel artifact identity.
    identity: ArtifactIdentity,
}

/// Final-link facts recovered from the MSVC map file.
#[derive(Debug)]
struct LinkMap {
    /// COFF timestamp recorded by the linker.
    timestamp: u32,
    /// Preferred image base recorded by the linker.
    image_base: u64,
    /// Absolute linked address of `DriverEntry`.
    driver_entry: u64,
    /// Absolute linked address of the identity bytes forced into the final image.
    artifact_identity: u64,
}

/// One initialized section of the on-disk PE image.
#[derive(Debug)]
struct PeSection {
    /// Relative virtual address where the section is linked.
    virtual_address: u32,
    /// Bytes actually present in the image file for this section.
    raw_data: core::ops::Range<usize>,
}

/// Final PE facts required to bind the map and signed image.
#[derive(Debug)]
struct PeImage {
    /// COFF timestamp from the image file header.
    timestamp: u32,
    /// Preferred image base from the optional header.
    image_base: u64,
    /// Entry-point relative virtual address.
    entry_rva: u32,
    /// Initialized PE sections used to resolve link-map addresses to file bytes.
    sections: Vec<PeSection>,
}

/// Classification for a forbidden production sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Sink {
    /// Rust panic, assertion, unwrap, or expect machinery.
    Panic,
    /// Bounds or slice-contract failure.
    Bounds,
    /// Length-mismatch copying helper.
    Copy,
    /// Standard-library sort machinery or comparator violation.
    Sort,
    /// Allocation failure terminal handler.
    OutOfMemory,
    /// Collection capacity overflow terminal handler.
    CapacityOverflow,
    /// Resumed async/Future execution.
    AsyncResume,
    /// Compiler trap or process abort.
    TrapOrAbort,
    /// Kernel-wide bugcheck boundary.
    KernelBugcheck,
}

impl Sink {
    /// Stable report category.
    const fn category(self) -> &'static str {
        match self {
            Self::Panic => "panic/assert/unwrap",
            Self::Bounds => "bounds/slice trap",
            Self::Copy => "copy trap",
            Self::Sort => "standard sort",
            Self::OutOfMemory => "OOM abort",
            Self::CapacityOverflow => "capacity overflow",
            Self::AsyncResume => "async/Future resume",
            Self::TrapOrAbort => "trap/abort",
            Self::KernelBugcheck => "KeBugCheckEx outside kernel::fatal",
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("production reachability gate error: {error}");
            ExitCode::from(2)
        }
    }
}

/// Executes artifact binding, parsing, analysis, and reporting.
///
/// # Errors
///
/// Returns an artifact, I/O, or LLVM parsing error before a verdict can be produced.
fn run() -> GateResult<bool> {
    let bundle = ArtifactBundle::load(command_line_artifacts()?)?;
    let module = IrModule::parse(&bundle.ir)?;
    let report = module.analyze_release()?;

    println!("production artifact identity: {}", bundle.identity.0);
    println!("release LLVM IR: {}", bundle.paths.ir.display());
    println!("release link map: {}", bundle.paths.link_map.display());
    println!("signed driver: {}", bundle.paths.driver.display());
    println!(
        "linked image: timestamp {:08x}, base {:016x}, DriverEntry {:016x}",
        bundle.link_map.timestamp, bundle.link_map.image_base, bundle.link_map.driver_entry
    );
    println!(
        "functions: {}, reachable: {}, address-taken: {}",
        report.function_count, report.reachable_count, report.address_taken_count
    );

    if report.violations.is_empty() {
        println!("production-root reachability gate: PASS");
        return Ok(true);
    }

    println!(
        "production-root reachability gate: FAIL ({} path(s))",
        report.violations.len()
    );
    for violation in &report.violations {
        println!("{}: {}", violation.category, violation.path.join(" -> "));
    }
    Ok(false)
}

/// Resolves the three explicit members of a production artifact bundle.
///
/// # Errors
///
/// Returns an error unless LLVM IR, link-map, and signed-driver paths are supplied exactly once.
fn command_line_artifacts() -> GateResult<ArtifactPaths> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let ir = arguments.next().ok_or(GateError::InvalidArguments)?;
    let link_map = arguments.next().ok_or(GateError::InvalidArguments)?;
    let driver = arguments.next().ok_or(GateError::InvalidArguments)?;
    if arguments.next().is_some() {
        return Err(GateError::InvalidArguments);
    }
    Ok(ArtifactPaths {
        ir: PathBuf::from(ir),
        link_map: PathBuf::from(link_map),
        driver: PathBuf::from(driver),
    })
}

impl ArtifactBundle {
    /// Loads and binds LLVM IR, link map, and signed PE by independent identities.
    ///
    /// # Errors
    ///
    /// Returns an I/O or artifact error when any input is absent, malformed, unsigned, or belongs
    /// to another compilation.
    fn load(paths: ArtifactPaths) -> GateResult<Self> {
        let ir = fs::read_to_string(&paths.ir).map_err(|source| GateError::Io {
            operation: "read LLVM IR",
            path: paths.ir.clone(),
            source,
        })?;
        let link_map_text =
            fs::read_to_string(&paths.link_map).map_err(|source| GateError::Io {
                operation: "read link map",
                path: paths.link_map.clone(),
                source,
            })?;
        let driver = fs::read(&paths.driver).map_err(|source| GateError::Io {
            operation: "read signed driver",
            path: paths.driver.clone(),
            source,
        })?;

        let ir_identity = ArtifactIdentity::parse(ir.as_bytes(), "LLVM IR")?;
        let driver_identity = ArtifactIdentity::parse(&driver, "signed driver")?;
        if ir_identity != driver_identity {
            return Err(GateError::InvalidArtifact(format!(
                "LLVM IR identity {} does not match signed-driver identity {}",
                ir_identity.0, driver_identity.0
            )));
        }

        let link_map = LinkMap::parse(&link_map_text)?;
        let image = PeImage::parse(&driver)?;
        link_map.verify_image(&image, &driver, &ir_identity)?;

        Ok(Self {
            paths,
            ir,
            link_map,
            identity: ir_identity,
        })
    }
}

impl ArtifactIdentity {
    /// Extracts the sole valid non-sentinel build identity from artifact bytes.
    ///
    /// # Errors
    ///
    /// Returns an artifact error when the marker is absent, malformed, ambiguous, or unverified.
    fn parse(bytes: &[u8], artifact: &'static str) -> GateResult<Self> {
        let mut identities = BTreeSet::new();
        let mut offset = 0_usize;
        while let Some(remaining) = bytes.get(offset..) {
            let Some(record) = remaining.get(..ARTIFACT_ID_RECORD_LENGTH) else {
                break;
            };
            let Some(candidate) = record.strip_prefix(ARTIFACT_ID_MARKER.as_bytes()) else {
                offset = checked_offset(offset, 1, "artifact identity scan")?;
                continue;
            };
            if candidate.iter().all(u8::is_ascii_hexdigit) {
                let identity = core::str::from_utf8(candidate).map_err(|error| {
                    GateError::InvalidArtifact(format!(
                        "{artifact} artifact identity is not UTF-8: {error}"
                    ))
                })?;
                identities.insert(identity.to_ascii_lowercase());
            }
            offset = checked_offset(offset, 1, "artifact identity scan")?;
        }

        if identities.len() != 1 {
            return Err(GateError::InvalidArtifact(format!(
                "{artifact} must contain exactly one 32-digit artifact identity; found {}",
                identities.len()
            )));
        }
        let identity = identities.into_iter().next().ok_or_else(|| {
            GateError::InvalidArtifact(format!("{artifact} artifact identity disappeared"))
        })?;
        if identity == UNVERIFIED_ARTIFACT_ID {
            return Err(GateError::InvalidArtifact(format!(
                "{artifact} carries the unverified developer-build identity"
            )));
        }
        Ok(Self(identity))
    }
}

impl LinkMap {
    /// Parses final-link identity fields and required production symbols.
    ///
    /// # Errors
    ///
    /// Returns an artifact error when a header field, entry point, or required linked symbol is
    /// absent or malformed.
    fn parse(map: &str) -> GateResult<Self> {
        for (role, symbol) in REQUIRED_LINKED_SYMBOLS {
            if !map.lines().any(|line| line.contains(symbol)) {
                return Err(GateError::InvalidArtifact(format!(
                    "link map omits {role} symbol containing {symbol}"
                )));
            }
        }

        let timestamp = map
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("Timestamp is ")
                    .and_then(|value| value.split_whitespace().next())
            })
            .ok_or_else(|| {
                GateError::InvalidArtifact("link map omits its COFF timestamp".to_owned())
            })?;
        let timestamp = parse_hex_u32(timestamp, "link-map timestamp")?;

        let image_base = map
            .lines()
            .find_map(|line| line.trim().strip_prefix("Preferred load address is "))
            .ok_or_else(|| {
                GateError::InvalidArtifact("link map omits its preferred image base".to_owned())
            })?;
        let image_base = parse_hex_u64(image_base.trim(), "link-map image base")?;

        let driver_entry = linked_symbol_address(map, DRIVER_ENTRY, "DriverEntry")?;
        let artifact_identity =
            linked_symbol_address(map, ARTIFACT_ID_SYMBOL, "artifact identity")?;

        Ok(Self {
            timestamp,
            image_base,
            driver_entry,
            artifact_identity,
        })
    }

    /// Verifies that this map describes the supplied final signed image.
    ///
    /// # Errors
    ///
    /// Returns an artifact error on any timestamp, base-address, or entry-point mismatch.
    fn verify_image(
        &self,
        image: &PeImage,
        image_bytes: &[u8],
        identity: &ArtifactIdentity,
    ) -> GateResult<()> {
        if self.timestamp != image.timestamp {
            return Err(GateError::InvalidArtifact(format!(
                "link-map timestamp {:08x} does not match PE timestamp {:08x}",
                self.timestamp, image.timestamp
            )));
        }
        if self.image_base != image.image_base {
            return Err(GateError::InvalidArtifact(format!(
                "link-map image base {:016x} does not match PE image base {:016x}",
                self.image_base, image.image_base
            )));
        }
        let image_entry = image
            .image_base
            .checked_add(u64::from(image.entry_rva))
            .ok_or_else(|| {
                GateError::InvalidArtifact("PE entry-point address overflows u64".to_owned())
            })?;
        if self.driver_entry != image_entry {
            return Err(GateError::InvalidArtifact(format!(
                "linked DriverEntry address {:016x} does not match PE entry point {:016x}",
                self.driver_entry, image_entry
            )));
        }
        let linked_identity = image.artifact_identity(image_bytes, self.artifact_identity)?;
        if &linked_identity != identity {
            return Err(GateError::InvalidArtifact(format!(
                "link-map artifact identity {} resolves to PE identity {}, not LLVM identity {}",
                self.artifact_identity, linked_identity.0, identity.0
            )));
        }
        Ok(())
    }
}

/// Recovers the absolute address recorded for one public symbol in an MSVC map.
///
/// # Errors
///
/// Returns an artifact error when the public-symbol row is absent or its address is malformed.
fn linked_symbol_address(map: &str, symbol: &str, role: &'static str) -> GateResult<u64> {
    let address = map.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let _section_offset = fields.next()?;
        (fields.next()? == symbol).then(|| fields.next()).flatten()
    });
    let address = address.ok_or_else(|| {
        GateError::InvalidArtifact(format!("link map omits the {role} public symbol {symbol}"))
    })?;
    parse_hex_u64(address, "linked public-symbol address")
}

impl PeImage {
    /// Parses and validates the final AMD64 native signed PE image.
    ///
    /// # Errors
    ///
    /// Returns an artifact error for truncated headers, a non-driver image, or an absent embedded
    /// Authenticode certificate table.
    fn parse(image: &[u8]) -> GateResult<Self> {
        if !image.starts_with(b"MZ") {
            return Err(GateError::InvalidArtifact(
                "signed driver has no DOS MZ header".to_owned(),
            ));
        }
        let pe_offset =
            usize::try_from(read_u32(image, 0x3c, "PE header offset")?).map_err(|error| {
                GateError::InvalidArtifact(format!("PE header offset does not fit usize: {error}"))
            })?;
        let signature_end = checked_offset(pe_offset, 4, "PE signature")?;
        let signature = image.get(pe_offset..signature_end).ok_or_else(|| {
            GateError::InvalidArtifact("signed driver has a truncated PE signature".to_owned())
        })?;
        if signature != b"PE\0\0" {
            return Err(GateError::InvalidArtifact(
                "signed driver has an invalid PE signature".to_owned(),
            ));
        }

        let coff = signature_end;
        if read_u16(image, coff, "COFF machine")? != IMAGE_FILE_MACHINE_AMD64 {
            return Err(GateError::InvalidArtifact(
                "signed driver is not an AMD64 image".to_owned(),
            ));
        }
        let section_count = usize::from(read_u16(
            image,
            checked_offset(coff, 2, "COFF section count")?,
            "COFF section count",
        )?);
        if section_count == 0 {
            return Err(GateError::InvalidArtifact(
                "signed driver has no initialized PE sections".to_owned(),
            ));
        }
        let timestamp_offset = checked_offset(coff, 4, "COFF timestamp")?;
        let timestamp = read_u32(image, timestamp_offset, "COFF timestamp")?;
        let optional_size_offset = checked_offset(coff, 16, "optional-header size")?;
        let optional_size = usize::from(read_u16(
            image,
            optional_size_offset,
            "optional-header size",
        )?);
        if optional_size < REQUIRED_OPTIONAL_HEADER_SIZE {
            return Err(GateError::InvalidArtifact(format!(
                "PE32+ optional header is too short for the certificate directory: {optional_size} bytes"
            )));
        }
        let optional = checked_offset(coff, 20, "optional header")?;
        let optional_end = checked_offset(optional, optional_size, "optional header")?;
        if image.get(optional..optional_end).is_none() {
            return Err(GateError::InvalidArtifact(
                "signed driver has a truncated optional header".to_owned(),
            ));
        }
        if read_u16(image, optional, "optional-header magic")? != PE32_PLUS_MAGIC {
            return Err(GateError::InvalidArtifact(
                "signed driver is not PE32+".to_owned(),
            ));
        }

        let entry_offset = checked_offset(optional, 16, "entry-point RVA")?;
        let entry_rva = read_u32(image, entry_offset, "entry-point RVA")?;
        let image_base_offset = checked_offset(optional, 24, "image base")?;
        let image_base = read_u64(image, image_base_offset, "image base")?;
        let subsystem_offset = checked_offset(optional, 68, "subsystem")?;
        if read_u16(image, subsystem_offset, "subsystem")? != IMAGE_SUBSYSTEM_NATIVE {
            return Err(GateError::InvalidArtifact(
                "signed driver does not use the native subsystem".to_owned(),
            ));
        }

        let certificate_offset_field = checked_offset(optional, 144, "certificate offset")?;
        let certificate_size_field = checked_offset(optional, 148, "certificate size")?;
        let certificate_size_field_end = checked_offset(
            certificate_size_field,
            core::mem::size_of::<u32>(),
            "certificate directory",
        )?;
        if certificate_size_field_end > optional_end {
            return Err(GateError::InvalidArtifact(
                "optional header omits the certificate data directory".to_owned(),
            ));
        }
        let certificate_offset = usize::try_from(read_u32(
            image,
            certificate_offset_field,
            "certificate offset",
        )?)
        .map_err(|error| {
            GateError::InvalidArtifact(format!("certificate offset does not fit usize: {error}"))
        })?;
        let certificate_size = usize::try_from(read_u32(
            image,
            certificate_size_field,
            "certificate size",
        )?)
        .map_err(|error| {
            GateError::InvalidArtifact(format!("certificate size does not fit usize: {error}"))
        })?;
        if certificate_offset == 0 || certificate_size == 0 {
            return Err(GateError::InvalidArtifact(
                "signed driver has no embedded Authenticode certificate table".to_owned(),
            ));
        }
        if certificate_offset.checked_rem(8) != Some(0)
            || certificate_size < WIN_CERTIFICATE_HEADER_SIZE
        {
            return Err(GateError::InvalidArtifact(
                "Authenticode certificate table has invalid alignment or length".to_owned(),
            ));
        }
        let certificate_end = checked_offset(
            certificate_offset,
            certificate_size,
            "Authenticode certificate table",
        )?;
        if image
            .get(certificate_offset..certificate_end)
            .is_none_or(<[u8]>::is_empty)
        {
            return Err(GateError::InvalidArtifact(
                "Authenticode certificate table lies outside the driver image".to_owned(),
            ));
        }
        let certificate_length = usize::try_from(read_u32(
            image,
            certificate_offset,
            "WIN_CERTIFICATE length",
        )?)
        .map_err(|error| {
            GateError::InvalidArtifact(format!(
                "WIN_CERTIFICATE length does not fit usize: {error}"
            ))
        })?;
        if certificate_length < WIN_CERTIFICATE_HEADER_SIZE || certificate_length > certificate_size
        {
            return Err(GateError::InvalidArtifact(
                "WIN_CERTIFICATE length lies outside its directory entry".to_owned(),
            ));
        }
        let certificate_revision_offset =
            checked_offset(certificate_offset, 4, "WIN_CERTIFICATE revision")?;
        if read_u16(
            image,
            certificate_revision_offset,
            "WIN_CERTIFICATE revision",
        )? != WIN_CERT_REVISION_2_0
        {
            return Err(GateError::InvalidArtifact(
                "WIN_CERTIFICATE revision is not 2.0".to_owned(),
            ));
        }
        let certificate_type_offset =
            checked_offset(certificate_offset, 6, "WIN_CERTIFICATE type")?;
        if read_u16(image, certificate_type_offset, "WIN_CERTIFICATE type")?
            != WIN_CERT_TYPE_PKCS_SIGNED_DATA
        {
            return Err(GateError::InvalidArtifact(
                "WIN_CERTIFICATE is not PKCS signed data".to_owned(),
            ));
        }

        let section_table = optional_end;
        let section_table_size = section_count.checked_mul(40).ok_or_else(|| {
            GateError::InvalidArtifact("PE section-table size overflows address space".to_owned())
        })?;
        let section_table_end =
            checked_offset(section_table, section_table_size, "PE section table")?;
        if image.get(section_table..section_table_end).is_none() {
            return Err(GateError::InvalidArtifact(
                "signed driver has a truncated PE section table".to_owned(),
            ));
        }
        let mut sections = Vec::new();
        sections
            .try_reserve_exact(section_count)
            .map_err(|source| GateError::Allocation {
                purpose: "PE section table",
                source,
            })?;
        for section_index in 0..section_count {
            let section_offset = checked_offset(
                section_table,
                section_index.checked_mul(40).ok_or_else(|| {
                    GateError::InvalidArtifact(
                        "PE section index overflows address space".to_owned(),
                    )
                })?,
                "PE section header",
            )?;
            let virtual_address = read_u32(
                image,
                checked_offset(section_offset, 12, "PE section virtual address")?,
                "PE section virtual address",
            )?;
            let raw_data_size = usize::try_from(read_u32(
                image,
                checked_offset(section_offset, 16, "PE section raw-data size")?,
                "PE section raw-data size",
            )?)
            .map_err(|error| {
                GateError::InvalidArtifact(format!(
                    "PE section raw-data size does not fit usize: {error}"
                ))
            })?;
            let raw_data_offset = usize::try_from(read_u32(
                image,
                checked_offset(section_offset, 20, "PE section raw-data offset")?,
                "PE section raw-data offset",
            )?)
            .map_err(|error| {
                GateError::InvalidArtifact(format!(
                    "PE section raw-data offset does not fit usize: {error}"
                ))
            })?;
            let raw_data_end =
                checked_offset(raw_data_offset, raw_data_size, "PE section raw data")?;
            if image.get(raw_data_offset..raw_data_end).is_none() {
                return Err(GateError::InvalidArtifact(format!(
                    "PE section {section_index} raw data lies outside the driver image"
                )));
            }
            sections.push(PeSection {
                virtual_address,
                raw_data: raw_data_offset..raw_data_end,
            });
        }

        Ok(Self {
            timestamp,
            image_base,
            entry_rva,
            sections,
        })
    }

    /// Resolves the map-addressed identity bytes from the exact signed PE image.
    ///
    /// # Errors
    ///
    /// Returns an artifact error when the link-map address is outside initialized PE bytes or does
    /// not contain one valid artifact marker.
    fn artifact_identity(&self, image: &[u8], linked_address: u64) -> GateResult<ArtifactIdentity> {
        let rva = linked_address.checked_sub(self.image_base).ok_or_else(|| {
            GateError::InvalidArtifact(format!(
                "link-map artifact symbol address {linked_address:016x} precedes PE image base {:016x}",
                self.image_base
            ))
        })?;
        let rva = u32::try_from(rva).map_err(|error| {
            GateError::InvalidArtifact(format!(
                "link-map artifact symbol RVA does not fit u32: {error}"
            ))
        })?;
        let marker_end = u64::from(rva)
            .checked_add(u64::try_from(ARTIFACT_ID_RECORD_LENGTH).map_err(|error| {
                GateError::InvalidArtifact(format!(
                    "artifact marker length does not fit u64: {error}"
                ))
            })?)
            .ok_or_else(|| {
                GateError::InvalidArtifact("artifact marker RVA overflows".to_owned())
            })?;
        for section in &self.sections {
            let section_start = u64::from(section.virtual_address);
            let section_length = u64::try_from(section.raw_data.len()).map_err(|error| {
                GateError::InvalidArtifact(format!("PE section length does not fit u64: {error}"))
            })?;
            let section_end = section_start.checked_add(section_length).ok_or_else(|| {
                GateError::InvalidArtifact("PE section RVA range overflows".to_owned())
            })?;
            if u64::from(rva) < section_start || marker_end > section_end {
                continue;
            }
            let within_section = u64::from(rva).checked_sub(section_start).ok_or_else(|| {
                GateError::InvalidArtifact(
                    "artifact marker RVA precedes its containing section".to_owned(),
                )
            })?;
            let within_section = usize::try_from(within_section).map_err(|error| {
                GateError::InvalidArtifact(format!(
                    "artifact marker section offset does not fit usize: {error}"
                ))
            })?;
            let marker_offset = checked_offset(
                section.raw_data.start,
                within_section,
                "artifact marker file offset",
            )?;
            let marker_end = checked_offset(
                marker_offset,
                ARTIFACT_ID_RECORD_LENGTH,
                "artifact marker file range",
            )?;
            let marker = image.get(marker_offset..marker_end).ok_or_else(|| {
                GateError::InvalidArtifact(
                    "artifact marker lies outside the driver image".to_owned(),
                )
            })?;
            return ArtifactIdentity::parse(marker, "link-map-addressed signed-driver marker");
        }
        Err(GateError::InvalidArtifact(format!(
            "link-map artifact symbol address {linked_address:016x} does not resolve to initialized PE bytes"
        )))
    }
}

/// Parses one hexadecimal `u32` artifact field.
///
/// # Errors
///
/// Returns an artifact error when `value` is not representable hexadecimal `u32` text.
fn parse_hex_u32(value: &str, field: &'static str) -> GateResult<u32> {
    u32::from_str_radix(value, 16)
        .map_err(|error| GateError::InvalidArtifact(format!("{field} is not hexadecimal: {error}")))
}

/// Parses one hexadecimal `u64` artifact field.
///
/// # Errors
///
/// Returns an artifact error when `value` is not representable hexadecimal `u64` text.
fn parse_hex_u64(value: &str, field: &'static str) -> GateResult<u64> {
    u64::from_str_radix(value, 16)
        .map_err(|error| GateError::InvalidArtifact(format!("{field} is not hexadecimal: {error}")))
}

/// Adds a PE offset without permitting wraparound.
///
/// # Errors
///
/// Returns an artifact error when the sum is not representable as `usize`.
fn checked_offset(base: usize, additional: usize, field: &'static str) -> GateResult<usize> {
    base.checked_add(additional).ok_or_else(|| {
        GateError::InvalidArtifact(format!("{field} offset overflows address space"))
    })
}

/// Reads a little-endian `u16` from a checked PE byte range.
///
/// # Errors
///
/// Returns an artifact error when the offset overflows or the field is truncated.
fn read_u16(bytes: &[u8], offset: usize, field: &'static str) -> GateResult<u16> {
    let end = checked_offset(offset, core::mem::size_of::<u16>(), field)?;
    let value: &[u8; 2] = bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| GateError::InvalidArtifact(format!("{field} is truncated")))?;
    Ok(u16::from_le_bytes(*value))
}

/// Reads a little-endian `u32` from a checked PE byte range.
///
/// # Errors
///
/// Returns an artifact error when the offset overflows or the field is truncated.
fn read_u32(bytes: &[u8], offset: usize, field: &'static str) -> GateResult<u32> {
    let end = checked_offset(offset, core::mem::size_of::<u32>(), field)?;
    let value: &[u8; 4] = bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| GateError::InvalidArtifact(format!("{field} is truncated")))?;
    Ok(u32::from_le_bytes(*value))
}

/// Reads a little-endian `u64` from a checked PE byte range.
///
/// # Errors
///
/// Returns an artifact error when the offset overflows or the field is truncated.
fn read_u64(bytes: &[u8], offset: usize, field: &'static str) -> GateResult<u64> {
    let end = checked_offset(offset, core::mem::size_of::<u64>(), field)?;
    let value: &[u8; 8] = bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| GateError::InvalidArtifact(format!("{field} is truncated")))?;
    Ok(u64::from_le_bytes(*value))
}

impl IrModule {
    /// Parses function declarations first, then builds body edges and roots.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a function header, graph edge, or the
    /// required `DriverEntry` root cannot be represented.
    fn parse(ir: &str) -> GateResult<Self> {
        let mut functions = BTreeMap::new();
        let mut pending_display: Option<String> = None;
        let mut inside_function = false;

        for (zero_based_line, line) in ir.lines().enumerate() {
            let trimmed = line.trim();
            if inside_function {
                if trimmed == "}" {
                    inside_function = false;
                }
                continue;
            }
            if let Some(comment) = function_name_comment(trimmed) {
                pending_display = Some(comment.to_owned());
                continue;
            }
            let definition = trimmed.starts_with("define ");
            let declaration = trimmed.starts_with("declare ");
            if !definition && !declaration {
                continue;
            }

            let symbol = function_symbol(trimmed).ok_or_else(|| {
                GateError::InvalidIr(format!(
                    "function without a symbol at line {}",
                    zero_based_line.saturating_add(1)
                ))
            })?;
            let signature = parse_function_signature(trimmed, &symbol).ok_or_else(|| {
                GateError::InvalidIr(format!(
                    "function signature could not be parsed for {symbol} at line {}",
                    zero_based_line.saturating_add(1)
                ))
            })?;
            let display = pending_display.take().unwrap_or_else(|| symbol.clone());
            let externally_visible = definition && definition_is_externally_visible(trimmed);
            functions.insert(
                symbol,
                Function {
                    display,
                    signature,
                    edges: BTreeSet::new(),
                    direct_calls: Vec::new(),
                    body: Vec::new(),
                    indirect_calls: Vec::new(),
                    returns: Vec::new(),
                    externally_visible,
                },
            );
            inside_function = definition;
        }

        if !functions.contains_key(DRIVER_ENTRY) {
            return Err(GateError::InvalidIr(
                "DriverEntry definition is absent from the release module".to_owned(),
            ));
        }

        let mut module = Self {
            functions,
            address_taken: BTreeSet::new(),
            roots: BTreeSet::new(),
        };
        module.collect_edges(ir)?;
        module.collect_roots();
        Ok(module)
    }

    /// Collects direct calls, function-address flows, and indirect call sites.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a symbol or function body boundary is
    /// malformed.
    fn collect_edges(&mut self, ir: &str) -> GateResult<()> {
        let mut current_function: Option<String> = None;
        let mut external_global = false;

        for (zero_based_line, line) in ir.lines().enumerate() {
            let trimmed = line.trim();
            if current_function.is_none() && trimmed.starts_with("define ") {
                current_function = function_symbol(trimmed);
                external_global = false;
                continue;
            }
            if current_function.is_none() && trimmed.starts_with("declare ") {
                external_global = false;
                continue;
            }
            if let Some(caller) = current_function.as_ref() {
                if trimmed == "}" {
                    current_function = None;
                    continue;
                }
                if trimmed.starts_with(';') {
                    continue;
                }
                self.collect_body_line(caller, line, zero_based_line.saturating_add(1))?;
                continue;
            }

            if trimmed.starts_with('@') && trimmed.contains(" = ") {
                external_global = !trimmed.contains(" private ")
                    && !trimmed.contains(" internal ")
                    && !trimmed.starts_with("@llvm.");
            } else if trimmed.is_empty()
                || trimmed.starts_with("declare ")
                || trimmed.starts_with("attributes ")
                || trimmed.starts_with('!')
                || trimmed.starts_with(';')
            {
                external_global = false;
            }

            let references = symbol_references(line)?;
            for reference in references {
                if !self.functions.contains_key(&reference) {
                    continue;
                }
                self.address_taken.insert(reference.clone());
                if external_global {
                    self.roots.insert(reference);
                }
            }
        }
        Ok(())
    }

    /// Adds graph facts recovered from one LLVM instruction line.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when `caller` is absent or a symbol boundary
    /// cannot be decoded.
    fn collect_body_line(
        &mut self,
        caller: &str,
        line: &str,
        line_number: usize,
    ) -> GateResult<()> {
        let call = parse_call_site(line);
        let direct_target = call.as_ref().and_then(|site| site.direct_target.as_ref());
        let references = symbol_references(line)?;
        let known_references: Vec<String> = references
            .into_iter()
            .filter(|reference| self.functions.contains_key(reference))
            .collect();

        let caller_node = self.functions.get_mut(caller).ok_or_else(|| {
            GateError::InvalidIr(format!("body found for unknown function {caller}"))
        })?;
        let trimmed = line.trim();
        caller_node.body.push(trimmed.to_owned());
        if trimmed.starts_with("ret ") {
            let return_instruction = trimmed
                .split_once(',')
                .map_or(trimmed, |(instruction, _metadata)| instruction);
            caller_node.returns.push(return_instruction.to_owned());
        }
        for reference in known_references {
            if direct_target == Some(&reference) {
                caller_node.direct_calls.push(reference.clone());
                caller_node.edges.insert(reference);
            } else {
                caller_node.edges.insert(reference.clone());
                self.address_taken.insert(reference);
            }
        }
        if let Some(site) = call
            && site.direct_target.is_none()
        {
            caller_node.indirect_calls.push(IndirectCall {
                signature: site.signature,
                line: line_number,
            });
        }
        Ok(())
    }

    /// Adds exported definitions and the driver entry point as roots.
    fn collect_roots(&mut self) {
        self.roots.insert(DRIVER_ENTRY.to_owned());
        for (symbol, function) in &self.functions {
            if function.externally_visible {
                self.roots.insert(symbol.clone());
            }
        }
    }

    /// Applies the complete ext4win release contract to a resolved production graph.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error if graph construction or a release boundary audit fails.
    fn analyze_release(mut self) -> GateResult<AnalysisReport> {
        let mut report = self.analyze_root_reachability()?;
        self.audit_release_contracts(&mut report.violations)?;
        Ok(report)
    }

    /// Resolves indirect calls and computes root-to-sink paths.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error if graph construction produced a missing or
    /// cyclic function node.
    fn analyze_root_reachability(&mut self) -> GateResult<AnalysisReport> {
        let address_taken_by_signature = self.address_taken_by_signature();
        let mut unresolved = BTreeMap::<String, Vec<IndirectCall>>::new();

        for (caller, function) in &mut self.functions {
            for indirect in &function.indirect_calls {
                let candidates = address_taken_by_signature.get(&indirect.signature);
                if let Some(candidates) = candidates.filter(|candidates| !candidates.is_empty()) {
                    function.edges.extend(candidates.iter().cloned());
                } else {
                    unresolved
                        .entry(caller.clone())
                        .or_default()
                        .push(indirect.clone());
                }
            }
        }

        let mut predecessors = BTreeMap::<String, Option<String>>::new();
        let mut queue = VecDeque::<String>::new();
        for root in &self.roots {
            if self.functions.contains_key(root) && !predecessors.contains_key(root) {
                predecessors.insert(root.clone(), None);
                queue.push_back(root.clone());
            }
        }

        while let Some(caller) = queue.pop_front() {
            let function = self.functions.get(&caller).ok_or_else(|| {
                GateError::InvalidIr(format!("reachable function {caller} disappeared"))
            })?;
            for callee in &function.edges {
                if !predecessors.contains_key(callee) {
                    predecessors.insert(callee.clone(), Some(caller.clone()));
                    queue.push_back(callee.clone());
                }
            }
        }

        let mut violations = Vec::new();
        let mut reported_sort_callers = BTreeSet::<String>::new();
        for symbol in predecessors.keys() {
            if violations.len() >= MAX_REPORTED_VIOLATIONS {
                break;
            }
            let function = self.functions.get(symbol).ok_or_else(|| {
                GateError::InvalidIr(format!("reachable symbol {symbol} has no function node"))
            })?;
            let Some(sink) = classify_sink(symbol, &function.display) else {
                continue;
            };
            if predecessor_contains_forbidden_sink(symbol, &predecessors, &self.functions) {
                continue;
            }
            if sink == Sink::Sort {
                let caller = predecessors
                    .get(symbol)
                    .and_then(Option::as_ref)
                    .cloned()
                    .unwrap_or_else(|| symbol.clone());
                if !reported_sort_callers.insert(caller) {
                    continue;
                }
            }
            if sink == Sink::KernelBugcheck
                && bugcheck_predecessor_is_allowed(symbol, &predecessors, &self.functions)
            {
                continue;
            }
            violations.push(Violation {
                category: sink.category(),
                path: display_path(symbol, &predecessors, &self.functions)?,
            });
        }

        self.append_reachable_unresolved_indirect_calls(
            &predecessors,
            &unresolved,
            &mut violations,
        )?;

        Ok(AnalysisReport {
            function_count: self.functions.len(),
            reachable_count: predecessors.len(),
            address_taken_count: self.address_taken.len(),
            violations,
        })
    }

    /// Applies lower-IRP and post-durability contracts that are stricter than general root
    /// reachability.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a contract path cannot be reconstructed.
    fn audit_release_contracts(&self, violations: &mut Vec<Violation>) -> GateResult<()> {
        self.audit_lower_submission(violations);
        self.audit_lower_completion_returns(violations);
        self.audit_nonallocating_callbacks(violations)?;
        self.audit_durable_publication(violations)
    }

    /// Requires every release monomorphization that registers lower completion to call the lower
    /// driver in the immediate registration-success block of the same sealed boundary.
    fn audit_lower_submission(&self, violations: &mut Vec<Violation>) {
        let mut registration_sites = 0_usize;
        for function in self.functions.values() {
            let registrations: Vec<usize> = function
                .body
                .iter()
                .enumerate()
                .filter_map(|(index, instruction)| {
                    instruction_calls(instruction, "IoSetCompletionRoutineEx").then_some(index)
                })
                .collect();
            if registrations.is_empty() {
                continue;
            }
            registration_sites = registration_sites.saturating_add(registrations.len());
            let submissions = function
                .body
                .iter()
                .filter(|instruction| instruction_calls(instruction, "IofCallDriver"))
                .count();
            let paired = registrations.len() == submissions
                && registrations.iter().copied().all(|registration| {
                    registration_success_calls_driver(&function.body, registration)
                });
            if !paired && violations.len() < MAX_REPORTED_VIOLATIONS {
                violations.push(Violation {
                    category: "lower submission protocol",
                    path: vec![
                        function.display.clone(),
                        "IoSetCompletionRoutineEx success must flow directly to one IofCallDriver"
                            .to_owned(),
                    ],
                });
            }
        }
        if registration_sites == 0 && violations.len() < MAX_REPORTED_VIOLATIONS {
            violations.push(Violation {
                category: "lower submission protocol",
                path: vec!["release module has no lower completion registration site".to_owned()],
            });
        }
    }

    /// Requires every concrete private-lower-IRP completion to stop I/O Manager processing.
    fn audit_lower_completion_returns(&self, violations: &mut Vec<Violation>) {
        let completions: Vec<&Function> = self
            .functions
            .values()
            .filter(|function| {
                function
                    .display
                    .starts_with("ext4win::irp::lower::lower_request_completed::<")
            })
            .collect();
        if completions.is_empty() && violations.len() < MAX_REPORTED_VIOLATIONS {
            violations.push(Violation {
                category: "lower completion protocol",
                path: vec!["release module has no private lower completion routine".to_owned()],
            });
            return;
        }
        for completion in completions {
            if !completion.returns.is_empty()
                && completion
                    .returns
                    .iter()
                    .all(|instruction| instruction == MORE_PROCESSING_REQUIRED_RETURN)
            {
                continue;
            }
            if violations.len() >= MAX_REPORTED_VIOLATIONS {
                return;
            }
            violations.push(Violation {
                category: "lower completion protocol",
                path: vec![
                    completion.display.clone(),
                    "every return must be STATUS_MORE_PROCESSING_REQUIRED".to_owned(),
                ],
            });
        }
    }

    /// Rejects allocation and blocking waits reachable from lower completion, active cancel, or
    /// retry-timer callbacks.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a callback path cannot be reconstructed.
    fn audit_nonallocating_callbacks(&self, violations: &mut Vec<Violation>) -> GateResult<()> {
        let roots: BTreeSet<String> = self
            .functions
            .iter()
            .filter_map(|(symbol, function)| {
                is_nonallocating_callback(&function.display).then_some(symbol.clone())
            })
            .collect();
        for required in [ACTIVE_CANCEL_CALLBACK, STORAGE_RETRY_CALLBACK] {
            if self
                .functions
                .values()
                .any(|function| function.display == required)
            {
                continue;
            }
            if violations.len() < MAX_REPORTED_VIOLATIONS {
                violations.push(Violation {
                    category: "callback protocol",
                    path: vec![format!("required release callback is absent: {required}")],
                });
            }
        }
        let predecessors = self.predecessors_from(&roots)?;
        let unresolved = self.unresolved_indirect_calls();
        self.append_reachable_unresolved_indirect_calls(&predecessors, &unresolved, violations)?;
        for symbol in predecessors.keys() {
            if violations.len() >= MAX_REPORTED_VIOLATIONS {
                break;
            }
            let function = self.functions.get(symbol).ok_or_else(|| {
                GateError::InvalidIr(format!("callback symbol {symbol} has no function node"))
            })?;
            if !is_callback_forbidden_sink(symbol, &function.display) {
                continue;
            }
            violations.push(Violation {
                category: "callback allocation/blocking",
                path: display_path(symbol, &predecessors, &self.functions)?,
            });
        }
        Ok(())
    }

    /// Rejects allocation, collection growth, or mutable CNG object creation reachable from the
    /// durable visibility publication boundary.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when an allocation path cannot be reconstructed.
    fn audit_durable_publication(&self, violations: &mut Vec<Violation>) -> GateResult<()> {
        let roots: BTreeSet<String> = self
            .functions
            .iter()
            .filter_map(|(symbol, function)| {
                (function.display == DURABLE_PUBLISH_ROOT).then_some(symbol.clone())
            })
            .collect();
        if roots.is_empty() {
            if violations.len() < MAX_REPORTED_VIOLATIONS {
                violations.push(Violation {
                    category: "post-commit allocation",
                    path: vec![format!(
                        "required release audit root is absent: {DURABLE_PUBLISH_ROOT}"
                    )],
                });
            }
            return Ok(());
        }
        let predecessors = self.predecessors_from(&roots)?;
        let unresolved = self.unresolved_indirect_calls();
        self.append_reachable_unresolved_indirect_calls(&predecessors, &unresolved, violations)?;
        for symbol in predecessors.keys() {
            if violations.len() >= MAX_REPORTED_VIOLATIONS {
                break;
            }
            let function = self.functions.get(symbol).ok_or_else(|| {
                GateError::InvalidIr(format!("publication symbol {symbol} has no function node"))
            })?;
            if !is_publication_allocation_sink(symbol, &function.display) {
                continue;
            }
            violations.push(Violation {
                category: "post-commit allocation",
                path: display_path(symbol, &predecessors, &self.functions)?,
            });
        }
        Ok(())
    }

    /// Computes shortest call paths from an explicit audit root set.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a reachable function node is absent.
    fn predecessors_from(
        &self,
        roots: &BTreeSet<String>,
    ) -> GateResult<BTreeMap<String, Option<String>>> {
        let mut predecessors = BTreeMap::<String, Option<String>>::new();
        let mut queue = VecDeque::<String>::new();
        for root in roots {
            if self.functions.contains_key(root) && !predecessors.contains_key(root) {
                predecessors.insert(root.clone(), None);
                queue.push_back(root.clone());
            }
        }
        while let Some(caller) = queue.pop_front() {
            let function = self.functions.get(&caller).ok_or_else(|| {
                GateError::InvalidIr(format!("audit function {caller} disappeared"))
            })?;
            for callee in &function.edges {
                if !predecessors.contains_key(callee) {
                    predecessors.insert(callee.clone(), Some(caller.clone()));
                    queue.push_back(callee.clone());
                }
            }
        }
        Ok(predecessors)
    }

    /// Recomputes the indirect call sites that have no compatible address-taken target.
    fn unresolved_indirect_calls(&self) -> BTreeMap<String, Vec<IndirectCall>> {
        let address_taken_by_signature = self.address_taken_by_signature();
        let mut unresolved = BTreeMap::<String, Vec<IndirectCall>>::new();
        for (caller, function) in &self.functions {
            for indirect in &function.indirect_calls {
                let has_candidate = address_taken_by_signature
                    .get(&indirect.signature)
                    .is_some_and(|candidates| !candidates.is_empty());
                if !has_candidate {
                    unresolved
                        .entry(caller.clone())
                        .or_default()
                        .push(indirect.clone());
                }
            }
        }
        unresolved
    }

    /// Reports unresolved execution reachable from any audit-root-specific traversal.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a path to the unresolved call cannot be reconstructed.
    fn append_reachable_unresolved_indirect_calls(
        &self,
        predecessors: &BTreeMap<String, Option<String>>,
        unresolved: &BTreeMap<String, Vec<IndirectCall>>,
        violations: &mut Vec<Violation>,
    ) -> GateResult<()> {
        for (caller, calls) in unresolved {
            if violations.len() >= MAX_REPORTED_VIOLATIONS {
                break;
            }
            if !predecessors.contains_key(caller) {
                continue;
            }
            for call in calls {
                if violations.len() >= MAX_REPORTED_VIOLATIONS {
                    break;
                }
                let mut path = display_path(caller, predecessors, &self.functions)?;
                path.push(format!(
                    "unresolved indirect call at LLVM IR line {} [{}]",
                    call.line, call.signature
                ));
                violations.push(Violation {
                    category: "unresolved indirect call",
                    path,
                });
            }
        }
        Ok(())
    }

    /// Groups address-taken functions by normalized LLVM signature.
    fn address_taken_by_signature(&self) -> BTreeMap<FunctionSignature, Vec<String>> {
        let mut grouped = BTreeMap::<FunctionSignature, Vec<String>>::new();
        for symbol in &self.address_taken {
            let Some(function) = self.functions.get(symbol) else {
                continue;
            };
            grouped
                .entry(function.signature.clone())
                .or_default()
                .push(symbol.clone());
        }
        grouped
    }
}

/// Intermediate representation of one direct or indirect call instruction.
#[derive(Debug)]
struct ParsedCallSite {
    /// Direct LLVM target, or `None` for an indirect call.
    direct_target: Option<String>,
    /// Normalized call-site signature.
    signature: FunctionSignature,
}

/// Parses a `call` or `invoke` instruction while tolerating LLVM attributes.
fn parse_call_site(line: &str) -> Option<ParsedCallSite> {
    let trimmed = line.trim();
    if trimmed.starts_with(';') {
        return None;
    }
    let (instruction_start, instruction_length) = call_instruction_start(line)?;
    let after_instruction = line.get(instruction_start.saturating_add(instruction_length)..)?;
    let direct = callable_symbol(after_instruction, '@');
    let indirect = callable_symbol(after_instruction, '%');
    let (callee_start, arguments_start, direct_target) = match (direct, indirect) {
        (Some((start, _arguments, _symbol)), Some((indirect_start, indirect_arguments, _)))
            if indirect_start < start =>
        {
            (indirect_start, indirect_arguments, None)
        }
        (Some((start, arguments, symbol)), _) => (start, arguments, Some(symbol)),
        (None, Some((start, arguments, _))) => (start, arguments, None),
        (None, None) => return None,
    };
    let arguments_end = matching_delimiter(after_instruction, arguments_start, '(', ')')?;
    let prefix = after_instruction.get(..callee_start)?;
    let arguments = after_instruction.get(arguments_start.saturating_add(1)..arguments_end)?;
    Some(ParsedCallSite {
        direct_target,
        signature: signature_from_parts(prefix, arguments),
    })
}

/// Locates the call-like instruction word and returns its byte range.
fn call_instruction_start(line: &str) -> Option<(usize, usize)> {
    let call = line.find("call ").map(|position| (position, "call ".len()));
    let invoke = line
        .find("invoke ")
        .map(|position| (position, "invoke ".len()));
    match (call, invoke) {
        (Some(call_site), Some(invoke_site)) if invoke_site.0 < call_site.0 => Some(invoke_site),
        (Some(call_site), _) => Some(call_site),
        (None, invoke_site) => invoke_site,
    }
}

/// Finds a symbol immediately followed by an argument list.
fn callable_symbol(input: &str, marker: char) -> Option<(usize, usize, String)> {
    for (position, character) in input.char_indices() {
        if character != marker {
            continue;
        }
        let symbol_start = position.saturating_add(marker.len_utf8());
        let tail = input.get(symbol_start..)?;
        let symbol_length = tail
            .char_indices()
            .take_while(|(_, candidate)| is_llvm_symbol_character(*candidate))
            .map(|(offset, candidate)| offset.saturating_add(candidate.len_utf8()))
            .last()?;
        let symbol_end = symbol_start.saturating_add(symbol_length);
        let after_symbol = input.get(symbol_end..)?.trim_start();
        if !after_symbol.starts_with('(') {
            continue;
        }
        let whitespace = input
            .get(symbol_end..)?
            .len()
            .saturating_sub(after_symbol.len());
        let arguments_start = symbol_end.saturating_add(whitespace);
        let symbol = input.get(symbol_start..symbol_end)?.to_owned();
        return Some((position, arguments_start, symbol));
    }
    None
}

/// Extracts a function symbol from a definition or declaration header.
fn function_symbol(header: &str) -> Option<String> {
    callable_symbol(header, '@').map(|(_, _, symbol)| symbol)
}

/// Parses the signature from a function header.
fn parse_function_signature(header: &str, symbol: &str) -> Option<FunctionSignature> {
    let marker = format!("@{symbol}");
    let symbol_start = header.find(&marker)?;
    let arguments_start = header
        .get(symbol_start.saturating_add(marker.len())..)?
        .find('(')?
        .saturating_add(symbol_start)
        .saturating_add(marker.len());
    let arguments_end = matching_delimiter(header, arguments_start, '(', ')')?;
    let prefix = header.get(..symbol_start)?;
    let arguments = header.get(arguments_start.saturating_add(1)..arguments_end)?;
    Some(signature_from_parts(prefix, arguments))
}

/// Normalizes a return prefix and a comma-separated argument list.
fn signature_from_parts(prefix: &str, arguments: &str) -> FunctionSignature {
    let result = last_llvm_type(prefix).unwrap_or_else(|| "?".to_owned());
    let mut parameters = Vec::new();
    let mut variadic = false;
    for argument in split_top_level(arguments, ',') {
        let trimmed = argument.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "..." {
            variadic = true;
            continue;
        }
        parameters.push(first_llvm_type(trimmed));
    }
    FunctionSignature {
        result,
        parameters,
        variadic,
    }
}

/// Returns the first top-level LLVM value type from an argument.
fn first_llvm_type(argument: &str) -> String {
    let trimmed = argument.trim_start();
    if trimmed.starts_with("ptr") {
        return "ptr".to_owned();
    }
    let token = trimmed.split_whitespace().next().unwrap_or("?");
    if is_scalar_llvm_type(token) {
        return token.to_owned();
    }
    if let Some(first) = trimmed.chars().next()
        && let Some(close) = matching_type_delimiter(first)
        && let Some(end) = matching_delimiter(trimmed, 0, first, close)
        && let Some(value_type) = trimmed.get(..=end)
    {
        return value_type.split_whitespace().collect();
    }
    "?".to_owned()
}

/// Returns the last scalar LLVM result type before a callee.
fn last_llvm_type(prefix: &str) -> Option<String> {
    prefix
        .split_whitespace()
        .rev()
        .map(|token| token.trim_matches(|character: char| character == ',' || character == ')'))
        .find(|token| is_scalar_llvm_type(token))
        .map(str::to_owned)
}

/// Recognizes scalar and opaque-pointer LLVM types used at ABI boundaries.
fn is_scalar_llvm_type(token: &str) -> bool {
    matches!(
        token,
        "void" | "ptr" | "half" | "bfloat" | "float" | "double" | "fp128" | "x86_fp80"
    ) || token.strip_prefix('i').is_some_and(|width| {
        !width.is_empty() && width.chars().all(|character| character.is_ascii_digit())
    })
}

/// Splits a string only at delimiters outside nested LLVM type/value groups.
fn split_top_level(input: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (position, character) in input.char_indices() {
        match character {
            '(' | '[' | '{' | '<' => depth = depth.saturating_add(1),
            ')' | ']' | '}' | '>' => depth = depth.saturating_sub(1),
            _ if character == delimiter && depth == 0 => {
                if let Some(part) = input.get(start..position) {
                    parts.push(part);
                }
                start = position.saturating_add(character.len_utf8());
            }
            _ => {}
        }
    }
    if let Some(part) = input.get(start..) {
        parts.push(part);
    }
    parts
}

/// Finds the matching close delimiter for a byte-positioned open delimiter.
fn matching_delimiter(input: &str, open_position: usize, open: char, close: char) -> Option<usize> {
    let tail = input.get(open_position..)?;
    let mut depth = 0usize;
    for (offset, character) in tail.char_indices() {
        if character == open {
            depth = depth.saturating_add(1);
        } else if character == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open_position.saturating_add(offset));
            }
        }
    }
    None
}

/// Maps an aggregate type opener to its closer.
const fn matching_type_delimiter(open: char) -> Option<char> {
    match open {
        '[' => Some(']'),
        '{' => Some('}'),
        '<' => Some('>'),
        _ => None,
    }
}

/// Extracts all unquoted LLVM symbol references from one line.
///
/// # Errors
///
/// Returns an invalid-IR error if a UTF-8 symbol boundary cannot be advanced.
fn symbol_references(line: &str) -> GateResult<Vec<String>> {
    let mut symbols = Vec::new();
    let mut remaining = line;
    while let Some(marker_position) = remaining.find('@') {
        let after_marker = remaining
            .get(marker_position.saturating_add(1)..)
            .ok_or_else(|| GateError::InvalidIr("invalid symbol boundary".to_owned()))?;
        let symbol_length = after_marker
            .char_indices()
            .take_while(|(_, character)| is_llvm_symbol_character(*character))
            .map(|(offset, character)| offset.saturating_add(character.len_utf8()))
            .last()
            .unwrap_or(0);
        if symbol_length > 0
            && let Some(symbol) = after_marker.get(..symbol_length)
        {
            symbols.push(symbol.to_owned());
        }
        let consumed = marker_position
            .saturating_add(1)
            .saturating_add(symbol_length);
        remaining = remaining
            .get(consumed..)
            .ok_or_else(|| GateError::InvalidIr("invalid symbol scan boundary".to_owned()))?;
    }
    Ok(symbols)
}

/// LLVM's unquoted global identifier character set needed by Rust output.
fn is_llvm_symbol_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '$' | '-')
}

/// Recovers a demangled function name comment preceding a definition.
fn function_name_comment(trimmed: &str) -> Option<&str> {
    let comment = trimmed.strip_prefix("; ")?;
    if comment.starts_with("Function Attrs:")
        || comment.starts_with("ModuleID")
        || comment.starts_with("source_filename")
    {
        return None;
    }
    Some(comment)
}

/// Determines whether a definition has externally visible LLVM linkage.
fn definition_is_externally_visible(header: &str) -> bool {
    !header.starts_with("define internal ")
        && !header.starts_with("define private ")
        && !header.starts_with("define linkonce_odr ")
        && !header.starts_with("define available_externally ")
}

/// Classifies forbidden terminal or prohibited-runtime functions.
fn classify_sink(symbol: &str, display: &str) -> Option<Sink> {
    let identity = format!("{display}\n{symbol}").to_ascii_lowercase();
    if identity.contains("kebugcheckex") {
        return Some(Sink::KernelBugcheck);
    }
    if identity.contains("copy_from_slice") || identity.contains("clone_from_slice") {
        return Some(Sink::Copy);
    }
    if identity.contains("core::slice::sort::") || identity.contains("panic_on_ord_violation") {
        return Some(Sink::Sort);
    }
    if identity.contains("panic_bounds_check")
        || identity.contains("slice_start_index_len_fail")
        || identity.contains("slice_end_index_len_fail")
        || identity.contains("slice_index_order_fail")
    {
        return Some(Sink::Bounds);
    }
    if identity.contains("handle_alloc_error")
        || identity.contains("__rust_alloc_error_handler")
        || identity.contains("rust_oom")
    {
        return Some(Sink::OutOfMemory);
    }
    if identity.contains("capacity_overflow") {
        return Some(Sink::CapacityOverflow);
    }
    if identity.contains("future") && identity.contains("poll")
        || identity.contains("async_fn")
        || identity.contains("{async")
    {
        return Some(Sink::AsyncResume);
    }
    if identity.contains("llvm.trap")
        || identity.contains("llvm.ubsantrap")
        || identity.contains("__fastfail")
        || identity == "abort\nabort"
    {
        return Some(Sink::TrapOrAbort);
    }
    if identity.contains("core::panicking::")
        || identity.contains("rust_begin_unwind")
        || identity.contains("unwrap_failed")
        || identity.contains("expect_failed")
        || identity.contains("assert_failed")
        || identity.contains("panic_fmt")
        || identity.contains("begin_panic")
    {
        return Some(Sink::Panic);
    }
    None
}

/// Recognizes operations forbidden after commit durability and before visibility publication.
fn is_publication_allocation_sink(symbol: &str, display: &str) -> bool {
    let identity = format!("{display}\n{symbol}").to_ascii_lowercase();
    identity.contains("exallocatepool")
        || identity.contains("ioallocateirp")
        || identity.contains("ioallocatemdl")
        || identity.contains("ioallocateworkitem")
        || identity.contains("mmallocatepagesformdl")
        || identity.contains("mmallocatecontiguousmemory")
        || identity.contains("bcryptopenalgorithmprovider")
        || identity.contains("bcryptcreatehash")
        || identity.contains("bcryptgeneratesymmetrickey")
}

/// Selects callbacks whose IRQL contract permits neither allocation nor blocking.
fn is_nonallocating_callback(display: &str) -> bool {
    display.starts_with("ext4win::irp::lower::lower_request_completed::<")
        || display == "ext4win::irp::cancel::active_irp_cancelled"
        || display == "ext4win::irp::reactor::storage_retry_timer_dpc"
}

/// Recognizes allocation, CNG construction, and blocking wait calls forbidden in callbacks.
fn is_callback_forbidden_sink(symbol: &str, display: &str) -> bool {
    if is_publication_allocation_sink(symbol, display) {
        return true;
    }
    let identity = format!("{display}\n{symbol}").to_ascii_lowercase();
    identity.contains("kewaitforsingleobject")
        || identity.contains("kewaitformultipleobjects")
        || identity.contains("zwwaitforsingleobject")
        || identity.contains("kedelayexecutionthread")
}

/// Returns whether one LLVM instruction directly invokes `target`.
fn instruction_calls(instruction: &str, target: &str) -> bool {
    parse_call_site(instruction)
        .and_then(|site| site.direct_target)
        .is_some_and(|callee| callee == target)
}

/// Verifies the fail/success typestate shape emitted by the sealed lower-registration boundary.
fn registration_success_calls_driver(body: &[String], registration: usize) -> bool {
    let Some(registration_instruction) = body.get(registration) else {
        return false;
    };
    let Some(registration_status) = assigned_ssa_value(registration_instruction) else {
        return false;
    };
    let Some(comparison) = body.get(registration.saturating_add(1)) else {
        return false;
    };
    let Some(comparison_result) = assigned_ssa_value(comparison) else {
        return false;
    };
    let Some((_, comparison_body)) = comparison.split_once('=') else {
        return false;
    };
    if comparison_body.trim() != format!("icmp slt i32 {registration_status}, 0") {
        return false;
    }
    let Some(branch) = body.get(registration.saturating_add(2)) else {
        return false;
    };
    let Some((_failure, success)) = conditional_branch_targets(branch, comparison_result) else {
        return false;
    };
    let Some(success_label) = body
        .iter()
        .enumerate()
        .skip(registration.saturating_add(3))
        .find_map(|(index, instruction)| {
            (basic_block_label(instruction) == Some(success)).then_some(index)
        })
    else {
        return false;
    };

    let mut submissions = 0_usize;
    for instruction in body.iter().skip(success_label.saturating_add(1)) {
        if basic_block_label(instruction).is_some() {
            return false;
        }
        if instruction_calls(instruction, "IofCallDriver") {
            submissions = submissions.saturating_add(1);
        }
        if is_terminator_instruction(instruction) {
            return submissions == 1;
        }
    }
    false
}

/// Extracts an SSA assignment name, including its leading percent sign.
fn assigned_ssa_value(instruction: &str) -> Option<&str> {
    let (assignment, _value) = instruction.split_once('=')?;
    let assignment = assignment.trim();
    assignment.starts_with('%').then_some(assignment)
}

/// Extracts the true and false labels from one conditional branch on `condition`.
fn conditional_branch_targets<'line>(
    instruction: &'line str,
    condition: &str,
) -> Option<(&'line str, &'line str)> {
    let prefix = format!("br i1 {condition}, label %");
    let targets = instruction.strip_prefix(&prefix)?;
    let (true_target, false_target) = targets.split_once(", label %")?;
    let false_target = false_target
        .split_once(',')
        .map_or(false_target, |(label, _)| label);
    Some((true_target.trim(), false_target.trim()))
}

/// Extracts a basic-block label without its LLVM predecessor comment.
fn basic_block_label(instruction: &str) -> Option<&str> {
    let (label, _suffix) = instruction.split_once(':')?;
    let label = label.trim();
    (!label.is_empty() && !label.chars().any(char::is_whitespace)).then_some(label)
}

/// Recognizes control-flow terminators that end the immediate registration-success block.
fn is_terminator_instruction(instruction: &str) -> bool {
    [
        "ret ",
        "br ",
        "switch ",
        "indirectbr ",
        "invoke ",
        "resume ",
        "unreachable",
        "callbr ",
        "catchswitch ",
        "catchret ",
        "cleanupret ",
    ]
    .iter()
    .any(|prefix| instruction.starts_with(prefix))
}

/// Returns whether the selected shortest path already crossed a forbidden sink.
fn predecessor_contains_forbidden_sink(
    symbol: &str,
    predecessors: &BTreeMap<String, Option<String>>,
    functions: &BTreeMap<String, Function>,
) -> bool {
    let mut current = predecessors.get(symbol).and_then(Option::as_deref);
    let mut remaining = predecessors.len();
    while let Some(predecessor) = current {
        if remaining == 0 {
            return true;
        }
        remaining = remaining.saturating_sub(1);
        let Some(function) = functions.get(predecessor) else {
            return true;
        };
        if classify_sink(predecessor, &function.display).is_some() {
            return true;
        }
        current = predecessors.get(predecessor).and_then(Option::as_deref);
    }
    false
}

/// Checks the exact immediate caller of the kernel bugcheck import.
fn bugcheck_predecessor_is_allowed(
    bugcheck: &str,
    predecessors: &BTreeMap<String, Option<String>>,
    functions: &BTreeMap<String, Function>,
) -> bool {
    let Some(Some(caller)) = predecessors.get(bugcheck) else {
        return false;
    };
    let Some(function) = functions.get(caller) else {
        return false;
    };
    FATAL_BUGCHECK_ALLOWLIST.contains(&function.display.as_str())
}

/// Reconstructs a root-to-node path without unchecked indexing.
///
/// # Errors
///
/// Returns an invalid-IR error when the predecessor graph has a missing node or
/// a cycle.
fn display_path(
    terminal: &str,
    predecessors: &BTreeMap<String, Option<String>>,
    functions: &BTreeMap<String, Function>,
) -> GateResult<Vec<String>> {
    let mut reversed = Vec::new();
    let mut current = Some(terminal);
    let mut remaining = predecessors.len().saturating_add(1);
    while let Some(symbol) = current {
        if remaining == 0 {
            return Err(GateError::InvalidIr(
                "predecessor graph contains a cycle".to_owned(),
            ));
        }
        remaining = remaining.saturating_sub(1);
        let function = functions.get(symbol).ok_or_else(|| {
            GateError::InvalidIr(format!("path symbol {symbol} has no function node"))
        })?;
        reversed.push(function.display.clone());
        current = predecessors
            .get(symbol)
            .ok_or_else(|| GateError::InvalidIr(format!("path predecessor missing for {symbol}")))?
            .as_deref();
    }
    let mut lower = 0_usize;
    let mut upper = reversed.len();
    while lower < upper {
        upper = upper
            .checked_sub(1)
            .ok_or_else(|| GateError::InvalidIr("path reversal index underflowed".to_owned()))?;
        if lower >= upper {
            break;
        }
        let (lower_values, upper_values) = reversed
            .split_at_mut_checked(upper)
            .ok_or_else(|| GateError::InvalidIr("path reversal split is invalid".to_owned()))?;
        let lower_value = lower_values.get_mut(lower).ok_or_else(|| {
            GateError::InvalidIr("path reversal lower index is invalid".to_owned())
        })?;
        let upper_value = upper_values.first_mut().ok_or_else(|| {
            GateError::InvalidIr("path reversal upper index is invalid".to_owned())
        })?;
        core::mem::swap(lower_value, upper_value);
        lower = lower
            .checked_add(1)
            .ok_or_else(|| GateError::InvalidIr("path reversal index overflowed".to_owned()))?;
    }
    Ok(reversed)
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_CANCEL_CALLBACK, ARTIFACT_ID_MARKER, AnalysisReport, ArtifactIdentity,
        DURABLE_PUBLISH_ROOT, GateError, IrModule, LinkMap, PeImage, Sink, classify_sink,
    };

    /// Builds a minimal driver-shaped LLVM fixture that activates every release contract audit.
    fn release_contract_fixture(
        submit_body: &str,
        completion_return: &str,
        publish_body: &str,
    ) -> String {
        format!(
            "; root\n\
             define void @DriverEntry() {{\n  call void @submit()\n  call void @publish()\n  ret void\n}}\n\
             ; submit\n\
             define internal void @submit() {{\n{submit_body}\n}}\n\
             ; ext4win::irp::lower::lower_request_completed::<fixture>\n\
             define internal i32 @complete(ptr %device, ptr %irp, ptr %context) {{\n  {completion_return}\n}}\n\
             ; ext4win::irp::cancel::active_irp_cancelled\n\
             define internal void @active_cancel(ptr %device, ptr %irp) {{\n  ret void\n}}\n\
             ; ext4win::irp::reactor::storage_retry_timer_dpc\n\
             define internal void @retry_timer(ptr %dpc, ptr %context, ptr %arg1, ptr %arg2) {{\n  ret void\n}}\n\
             ; <ext4win::state::volume::MountedVolumeAccess>::publish_durable\n\
             define internal void @publish() {{\n{publish_body}\n  ret void\n}}\n\
             declare i32 @IoSetCompletionRoutineEx(ptr, ptr, ptr, ptr, i8, i8, i8)\n\
             declare i32 @IofCallDriver(ptr, ptr)\n\
             declare ptr @ExAllocatePool2(i64, i64, i32)\n\
             declare ptr @IoAllocateIrp(i8, i8)\n"
        )
    }

    /// Emits the exact registration-failure/success split accepted by the release contract.
    fn successful_lower_submission() -> &'static str {
        "  %registered = call i32 @IoSetCompletionRoutineEx(ptr null, ptr null, ptr @complete, ptr null, i8 1, i8 1, i8 1)\n\
           %failed = icmp slt i32 %registered, 0\n\
           br i1 %failed, label %registration_failed, label %registration_succeeded\n\
         registration_failed:\n\
           ret void\n\
         registration_succeeded:\n\
           %submitted = call i32 @IofCallDriver(ptr null, ptr null)\n\
           ret void"
    }

    /// Emits a malformed success branch that returns without submitting the registered request.
    fn missing_lower_submission() -> &'static str {
        "  %registered = call i32 @IoSetCompletionRoutineEx(ptr null, ptr null, ptr @complete, ptr null, i8 1, i8 1, i8 1)\n\
           %failed = icmp slt i32 %registered, 0\n\
           br i1 %failed, label %registration_failed, label %registration_succeeded\n\
         registration_failed:\n\
           ret void\n\
         registration_succeeded:\n\
           ret void"
    }

    /// Emits one textual submit call that remains bypassable from the registration-success block.
    fn bypassable_lower_submission() -> &'static str {
        "  %registered = call i32 @IoSetCompletionRoutineEx(ptr null, ptr null, ptr @complete, ptr null, i8 1, i8 1, i8 1)\n\
           %failed = icmp slt i32 %registered, 0\n\
           br i1 %failed, label %registration_failed, label %registration_succeeded\n\
         registration_failed:\n\
           ret void\n\
         registration_succeeded:\n\
           br i1 true, label %submit, label %escape\n\
         submit:\n\
           %submitted = call i32 @IofCallDriver(ptr null, ptr null)\n\
           ret void\n\
         escape:\n\
           ret void"
    }

    /// Parses and runs only the reusable production-root graph analysis for focused fixtures.
    ///
    /// # Errors
    ///
    /// Returns the parser or graph-analysis failure for `fixture`.
    fn analyze_root_fixture(fixture: &str) -> Result<AnalysisReport, super::GateError> {
        let mut module = IrModule::parse(fixture)?;
        module.analyze_root_reachability()
    }

    /// Converts a failed test invariant into the analyzer's structured error.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when `condition` is false.
    fn require(condition: bool, detail: &'static str) -> Result<(), super::GateError> {
        if condition {
            Ok(())
        } else {
            Err(super::GateError::InvalidIr(detail.to_owned()))
        }
    }

    /// Produces a minimal MSVC map containing every production symbol required by the gate.
    fn link_map_fixture(
        timestamp: u32,
        image_base: u64,
        driver_entry: u64,
        artifact_identity: u64,
    ) -> String {
        format!(
            " ext4win\n Timestamp is {timestamp:08x} (fixture)\n\
             Preferred load address is {image_base:016x}\n\
             0001:00001000 DriverEntry {driver_entry:016x} f ext4win.o\n\
             0002:00000000 EXT4WIN_PRODUCTION_ARTIFACT_ID {artifact_identity:016x} f ext4win.o\n\
             active_irp_cancelled\n\
             storage_retry_timer_dpc\n\
             lower_request_completed\n\
             publish_durable\n\
             IoSetCompletionRoutineEx\n\
             IofCallDriver\n\
             ext4win_stream_create\n\
             ext4win_stream_decode_owner\n\
             ext4win_stream_section_objects\n\
             ext4win_stream_get_sizes\n\
             ext4win_stream_set_sizes\n\
             ext4win_stream_destroy\n\
             ext4win_stream_cache_initialize\n\
             ext4win_stream_cache_read\n\
             ext4win_stream_cache_write\n\
             ext4win_stream_cache_flush\n\
             ext4win_stream_cache_coherency_flush_and_purge\n\
             ext4win_stream_cache_uninitialize\n\
             ext4win_stream_oplock_fsctrl\n\
             FsRtlOplockFsctrlEx\n\
             ext4win_fast_io_dispatch\n\
             ext4win_fast_io_read\n\
             ext4win_fast_io_write\n\
             ext4win_trace_register\n\
             ext4win_trace_write\n\
             ext4win_trace_unregister\n\
             EtwRegister\n\
             EtwEventEnabled\n\
             EtwWrite\n\
             EtwUnregister\n\
             ext4win_query_volume_partition\n\
             ext4win_read_volume_prefix\n\
             ext4win_announce_volume\n\
             raw_volume\n\
             EXT4WIN_PRODUCTION_ARTIFACT_ID\n"
        )
    }

    /// Writes one byte range without unchecked indexing or slice-copy panics.
    ///
    /// # Errors
    ///
    /// Returns an artifact error when the fixture range is not representable or exceeds the image.
    fn write_bytes(destination: &mut [u8], offset: usize, value: &[u8]) -> Result<(), GateError> {
        let end = offset.checked_add(value.len()).ok_or_else(|| {
            GateError::InvalidArtifact("fixture write offset overflowed".to_owned())
        })?;
        let output = destination.get_mut(offset..end).ok_or_else(|| {
            GateError::InvalidArtifact("fixture write exceeded the PE image".to_owned())
        })?;
        for (output_byte, value_byte) in output.iter_mut().zip(value) {
            *output_byte = *value_byte;
        }
        Ok(())
    }

    /// Produces a minimal AMD64 native PE candidate with an optional certificate table.
    ///
    /// # Errors
    ///
    /// Returns an artifact error if a fixture field cannot be placed in its fixed image buffer.
    fn pe_fixture(has_certificate: bool) -> Result<Vec<u8>, GateError> {
        let mut image = vec![0_u8; 0x380];
        write_bytes(&mut image, 0, b"MZ")?;
        write_bytes(&mut image, 0x3c, &0x80_u32.to_le_bytes())?;
        write_bytes(&mut image, 0x80, b"PE\0\0")?;
        write_bytes(&mut image, 0x84, &0x8664_u16.to_le_bytes())?;
        write_bytes(&mut image, 0x86, &1_u16.to_le_bytes())?;
        write_bytes(&mut image, 0x88, &0x1234_5678_u32.to_le_bytes())?;
        write_bytes(&mut image, 0x94, &0x00f0_u16.to_le_bytes())?;
        write_bytes(&mut image, 0x98, &0x020b_u16.to_le_bytes())?;
        write_bytes(&mut image, 0xa8, &0x1000_u32.to_le_bytes())?;
        write_bytes(&mut image, 0xb0, &0x0000_0001_8000_0000_u64.to_le_bytes())?;
        write_bytes(&mut image, 0xdc, &1_u16.to_le_bytes())?;
        write_bytes(&mut image, 0x190, &0x100_u32.to_le_bytes())?;
        write_bytes(&mut image, 0x194, &0x2000_u32.to_le_bytes())?;
        write_bytes(&mut image, 0x198, &0x100_u32.to_le_bytes())?;
        write_bytes(&mut image, 0x19c, &0x200_u32.to_le_bytes())?;
        write_bytes(
            &mut image,
            0x200,
            format!("{ARTIFACT_ID_MARKER}0123456789abcdef0123456789abcdef").as_bytes(),
        )?;
        if has_certificate {
            write_bytes(&mut image, 0x128, &0x300_u32.to_le_bytes())?;
            write_bytes(&mut image, 0x12c, &0x40_u32.to_le_bytes())?;
            write_bytes(&mut image, 0x300, &0x20_u32.to_le_bytes())?;
            write_bytes(&mut image, 0x304, &0x0200_u16.to_le_bytes())?;
            write_bytes(&mut image, 0x306, &0x0002_u16.to_le_bytes())?;
            write_bytes(&mut image, 0x308, b"certificate-table-fixture")?;
        }
        Ok(image)
    }

    /// The build identity must be unique, hexadecimal, and non-sentinel in every artifact.
    ///
    /// # Errors
    ///
    /// Returns an error if a valid marker is rejected or invalid identities are accepted.
    #[test]
    fn artifact_identity_is_fail_closed() -> Result<(), GateError> {
        let valid = format!("{ARTIFACT_ID_MARKER}0123456789abcdef0123456789ABCDEF");
        let parsed = ArtifactIdentity::parse(valid.as_bytes(), "fixture")?;
        require(
            parsed.0 == "0123456789abcdef0123456789abcdef",
            "valid artifact identity was not normalized",
        )?;

        let sentinel = format!("{ARTIFACT_ID_MARKER}00000000000000000000000000000000");
        require(
            ArtifactIdentity::parse(sentinel.as_bytes(), "fixture").is_err(),
            "unverified artifact identity was accepted",
        )?;

        let ambiguous = format!(
            "{ARTIFACT_ID_MARKER}0123456789abcdef0123456789abcdef\n\
             {ARTIFACT_ID_MARKER}fedcba9876543210fedcba9876543210"
        );
        require(
            ArtifactIdentity::parse(ambiguous.as_bytes(), "fixture").is_err(),
            "ambiguous artifact identities were accepted",
        )
    }

    /// Map timestamp, image base, `DriverEntry`, and marker address must identify the signed PE.
    ///
    /// # Errors
    ///
    /// Returns an error if a matching pair is rejected or a mismatched entry point is accepted.
    #[test]
    fn link_map_is_bound_to_signed_pe() -> Result<(), GateError> {
        let image_bytes = pe_fixture(true)?;
        let image = PeImage::parse(&image_bytes)?;
        let identity = ArtifactIdentity::parse(
            format!("{ARTIFACT_ID_MARKER}0123456789abcdef0123456789abcdef").as_bytes(),
            "fixture",
        )?;
        let matching = LinkMap::parse(&link_map_fixture(
            0x1234_5678,
            0x0000_0001_8000_0000,
            0x0000_0001_8000_1000,
            0x0000_0001_8000_2000,
        ))?;
        matching.verify_image(&image, &image_bytes, &identity)?;

        let mismatched = LinkMap::parse(&link_map_fixture(
            0x1234_5678,
            0x0000_0001_8000_0000,
            0x0000_0001_8000_2000,
            0x0000_0001_8000_2000,
        ))?;
        require(
            mismatched
                .verify_image(&image, &image_bytes, &identity)
                .is_err(),
            "mismatched DriverEntry address was accepted",
        )?;

        let marker_mismatch = LinkMap::parse(&link_map_fixture(
            0x1234_5678,
            0x0000_0001_8000_0000,
            0x0000_0001_8000_1000,
            0x0000_0001_8000_2008,
        ))?;
        require(
            marker_mismatch
                .verify_image(&image, &image_bytes, &identity)
                .is_err(),
            "map artifact-symbol address not pointing at the marker was accepted",
        )?;

        let mut mismatched_marker_bytes = image_bytes.clone();
        write_bytes(
            &mut mismatched_marker_bytes,
            0x200,
            format!("{ARTIFACT_ID_MARKER}fedcba9876543210fedcba9876543210").as_bytes(),
        )?;
        let mismatched_marker_image = PeImage::parse(&mismatched_marker_bytes)?;
        require(
            matching
                .verify_image(
                    &mismatched_marker_image,
                    &mismatched_marker_bytes,
                    &identity,
                )
                .is_err(),
            "map-addressed marker with a different identity was accepted",
        )
    }

    /// The final map must retain every production callback and protocol boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if removing a required linked callback is not detected.
    #[test]
    fn link_map_requires_production_roots() -> Result<(), GateError> {
        let map = link_map_fixture(
            0x1234_5678,
            0x0000_0001_8000_0000,
            0x0000_0001_8000_1000,
            0x0000_0001_8000_2000,
        )
        .replace("active_irp_cancelled", "missing_cancel_callback");
        require(
            LinkMap::parse(&map).is_err(),
            "link map without active cancellation callback was accepted",
        )
    }

    /// A native PE without an embedded Authenticode certificate table is not a production input.
    ///
    /// # Errors
    ///
    /// Returns an error if the unsigned candidate is accepted.
    #[test]
    fn unsigned_pe_is_rejected() -> Result<(), GateError> {
        require(
            PeImage::parse(&pe_fixture(false)?).is_err(),
            "PE without certificate table was accepted",
        )
    }

    /// Unreachable language-item sinks must not fail the production graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the invariant fails.
    #[test]
    fn unreachable_panic_is_allowed() -> Result<(), super::GateError> {
        let report = analyze_root_fixture(
            "; root\ndefine void @DriverEntry() {\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?;
        require(
            report.violations.is_empty(),
            "unreachable panic was reported",
        )
    }

    /// A direct reachable panic reports the full root path.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the expected path is
    /// absent.
    #[test]
    fn reachable_panic_reports_path() -> Result<(), super::GateError> {
        let report = analyze_root_fixture(
            "; root\ndefine void @DriverEntry() {\n  call void @work()\n  ret void\n}\n\
             ; work\ndefine internal void @work() {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?;
        let Some(violation) = report.violations.first() else {
            return Err(super::GateError::InvalidIr(
                "expected a reachable panic violation".to_owned(),
            ));
        };
        require(
            violation.path.join(" -> ") == "root -> work -> core::panicking::panic_fmt",
            "reachable panic path differed",
        )
    }

    /// Function addresses stored by a root become callback edges.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the callback path is
    /// not reported exactly once.
    #[test]
    fn address_store_roots_callback() -> Result<(), super::GateError> {
        let report = analyze_root_fixture(
            "; root\ndefine void @DriverEntry(ptr %slot) {\n  store ptr @callback, ptr %slot\n  ret void\n}\n\
             ; callback\ndefine internal void @callback() {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?;
        require(
            report.violations.len() == 1,
            "stored callback did not produce one violation",
        )
    }

    /// Unknown indirect calls with no typed candidate fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or unresolved execution
    /// is not rejected.
    #[test]
    fn unresolved_indirect_call_fails_closed() -> Result<(), super::GateError> {
        let report = analyze_root_fixture(
            "; root\ndefine void @DriverEntry(ptr %callback) {\n  call i32 %callback(i64 1)\n  ret void\n}\n",
        )?;
        let Some(violation) = report.violations.first() else {
            return Err(super::GateError::InvalidIr(
                "expected an unresolved indirect violation".to_owned(),
            ));
        };
        require(
            violation.category == "unresolved indirect call",
            "indirect call did not fail closed",
        )
    }

    /// Indirect calls expand to every address-taken compatible function.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the typed target is
    /// not connected.
    #[test]
    fn indirect_call_reaches_typed_address_target() -> Result<(), super::GateError> {
        let report = analyze_root_fixture(
            "; root\ndefine void @DriverEntry(ptr %slot, ptr %callback) {\n  store ptr @typed, ptr %slot\n  call void %callback(ptr null)\n  ret void\n}\n\
             ; typed\ndefine internal void @typed(ptr %value) {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?;
        require(
            report
                .violations
                .iter()
                .any(|violation| violation.category == Sink::Panic.category()),
            "typed indirect target was not reached",
        )
    }

    /// Callback-only roots fail closed when their indirect callee has no typed target.
    ///
    /// # Errors
    ///
    /// Returns an error if callback reachability ignores unresolved execution.
    #[test]
    fn callback_audit_rejects_unresolved_indirect_call() -> Result<(), super::GateError> {
        let module = IrModule::parse(&release_contract_fixture(
            successful_lower_submission(),
            "call void %callback(ptr null)\n  ret i32 -1073741802",
            "",
        ))?;
        let mut violations = Vec::new();
        module.audit_nonallocating_callbacks(&mut violations)?;
        require(
            violations
                .iter()
                .any(|violation| violation.category == "unresolved indirect call"),
            "callback audit accepted an unresolved indirect call",
        )
    }

    /// The durable-publication root fails closed when its indirect callee is unresolved.
    ///
    /// # Errors
    ///
    /// Returns an error if publication reachability ignores unresolved execution.
    #[test]
    fn durable_publication_audit_rejects_unresolved_indirect_call() -> Result<(), super::GateError>
    {
        let module = IrModule::parse(&release_contract_fixture(
            successful_lower_submission(),
            "ret i32 -1073741802",
            "call void %callback(ptr null)",
        ))?;
        let mut violations = Vec::new();
        module.audit_durable_publication(&mut violations)?;
        require(
            violations
                .iter()
                .any(|violation| violation.category == "unresolved indirect call"),
            "durable-publication audit accepted an unresolved indirect call",
        )
    }

    /// Only the enumerated fatal function may invoke the bugcheck import.
    ///
    /// # Errors
    ///
    /// Returns an error if a fixture cannot be parsed or the bugcheck allowlist
    /// admits the wrong caller.
    #[test]
    fn bugcheck_requires_enumerated_caller() -> Result<(), super::GateError> {
        let allowed = analyze_root_fixture(
            "; root\ndefine void @DriverEntry() {\n  call void @fatal()\n  ret void\n}\n\
             ; <ext4win::kernel::fatal::KernelWideInconsistency>::bugcheck\n\
             define internal void @fatal() {\n  call void @KeBugCheckEx()\n  ret void\n}\n\
             declare void @KeBugCheckEx()\n",
        )?;
        require(
            allowed.violations.is_empty(),
            "enumerated fatal caller was rejected",
        )?;

        let rejected = analyze_root_fixture(
            "; root\ndefine void @DriverEntry() {\n  call void @wrong()\n  ret void\n}\n\
             ; wrong\ndefine internal void @wrong() {\n  call void @KeBugCheckEx()\n  ret void\n}\n\
             declare void @KeBugCheckEx()\n",
        )?;
        require(
            rejected.violations.len() == 1,
            "non-fatal bugcheck caller was accepted",
        )
    }

    /// Sink classification includes the explicit non-panic terminal classes.
    ///
    /// # Errors
    ///
    /// Returns an error if a required sink class is absent.
    #[test]
    fn terminal_sink_classes_are_explicit() -> Result<(), super::GateError> {
        require(
            classify_sink("oom", "alloc::alloc::handle_alloc_error") == Some(Sink::OutOfMemory),
            "OOM sink class is absent",
        )?;
        require(
            classify_sink("copy", "core::slice::<impl [T]>::copy_from_slice") == Some(Sink::Copy),
            "copy sink class is absent",
        )?;
        require(
            classify_sink("sort", "core::slice::sort::stable::sort") == Some(Sink::Sort),
            "sort sink class is absent",
        )
    }

    /// Only the first forbidden node on a selected path is reported.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or nested terminal
    /// machinery produces redundant paths.
    #[test]
    fn nested_sinks_report_frontier_only() -> Result<(), super::GateError> {
        let report = analyze_root_fixture(
            "; root\ndefine void @DriverEntry() {\n  call void @sort_entry()\n  ret void\n}\n\
             ; core::slice::sort::stable::driftsort_main\n\
             define internal void @sort_entry() {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?;
        require(
            report.violations.len() == 1
                && report
                    .violations
                    .first()
                    .is_some_and(|violation| violation.category == Sink::Sort.category()),
            "nested sinks were not collapsed to the frontier",
        )
    }

    /// The release lower protocol accepts one paired registration/submission and only the private
    /// completion stop status.
    ///
    /// # Errors
    ///
    /// Returns an error if the valid fixture is rejected or either protocol regression is missed.
    #[test]
    fn lower_release_protocol_is_artifact_checked() -> Result<(), super::GateError> {
        let valid =
            release_contract_fixture(successful_lower_submission(), "ret i32 -1073741802", "");
        require(
            IrModule::parse(&valid)?
                .analyze_release()?
                .violations
                .is_empty(),
            "valid lower release protocol was rejected",
        )?;

        let missing_submit =
            release_contract_fixture(missing_lower_submission(), "ret i32 -1073741802", "");
        let missing_submit = IrModule::parse(&missing_submit)?.analyze_release()?;
        require(
            missing_submit
                .violations
                .iter()
                .any(|violation| violation.category == "lower submission protocol"),
            "registration without lower submission was accepted",
        )?;

        let bypassable_submit =
            release_contract_fixture(bypassable_lower_submission(), "ret i32 -1073741802", "");
        let bypassable_submit = IrModule::parse(&bypassable_submit)?.analyze_release()?;
        require(
            bypassable_submit
                .violations
                .iter()
                .any(|violation| violation.category == "lower submission protocol"),
            "a registration-success path that bypasses lower submission was accepted",
        )?;

        let wrong_completion =
            release_contract_fixture(successful_lower_submission(), "ret i32 0", "");
        let wrong_completion = IrModule::parse(&wrong_completion)?.analyze_release()?;
        require(
            wrong_completion
                .violations
                .iter()
                .any(|violation| violation.category == "lower completion protocol"),
            "completion status other than MORE_PROCESSING_REQUIRED was accepted",
        )?;

        let allocating_completion = release_contract_fixture(
            successful_lower_submission(),
            "%allocation = call ptr @ExAllocatePool2(i64 64, i64 32, i32 1)\n  ret i32 -1073741802",
            "",
        );
        let allocating_completion = IrModule::parse(&allocating_completion)?.analyze_release()?;
        require(
            allocating_completion
                .violations
                .iter()
                .any(|violation| violation.category == "callback allocation/blocking"),
            "allocating completion callback was accepted",
        )?;

        let private_irp_allocating_completion = release_contract_fixture(
            successful_lower_submission(),
            "%allocation = call ptr @IoAllocateIrp(i8 1, i8 0)\n  ret i32 -1073741802",
            "",
        );
        let private_irp_allocating_completion =
            IrModule::parse(&private_irp_allocating_completion)?.analyze_release()?;
        require(
            private_irp_allocating_completion
                .violations
                .iter()
                .any(|violation| violation.category == "callback allocation/blocking"),
            "private IRP allocation from a completion callback was accepted",
        )
    }

    /// Callback auditing must conservatively follow every resolved indirect target.
    ///
    /// # Errors
    ///
    /// Returns an error if an allocation reachable only through an indirect callback call is
    /// omitted from the callback-specific report.
    #[test]
    fn callback_audit_follows_resolved_indirect_targets() -> Result<(), super::GateError> {
        let mut fixture = release_contract_fixture(
            successful_lower_submission(),
            "call void %context()\n  ret i32 -1073741802",
            "",
        );
        fixture.push_str(
            "@destination = internal global ptr @allocating_destination\n\
             ; fixture::allocating_destination\n\
             define internal void @allocating_destination() {\n\
               %allocation = call ptr @ExAllocatePool2(i64 64, i64 32, i32 1)\n\
               ret void\n\
             }\n",
        );
        let report = IrModule::parse(&fixture)?.analyze_release()?;
        require(
            report
                .violations
                .iter()
                .any(|violation| violation.category == "callback allocation/blocking"),
            "allocation through a resolved indirect callback target was accepted",
        )
    }

    /// Release audits must not disappear when an unrelated allocator import is absent.
    ///
    /// # Errors
    ///
    /// Returns an error if the malformed lower protocol is accepted after removing the allocator
    /// declaration that previously acted as a fail-open activation sentinel.
    #[test]
    fn release_contracts_do_not_depend_on_allocator_imports() -> Result<(), super::GateError> {
        let fixture =
            release_contract_fixture(missing_lower_submission(), "ret i32 -1073741802", "")
                .replace("declare ptr @ExAllocatePool2(i64, i64, i32)\n", "");
        let report = IrModule::parse(&fixture)?.analyze_release()?;
        require(
            report
                .violations
                .iter()
                .any(|violation| violation.category == "lower submission protocol"),
            "allocator import removal disabled lower protocol auditing",
        )
    }

    /// Required callback and durable-publication roots are part of the release artifact contract.
    ///
    /// # Errors
    ///
    /// Returns an error if either missing root is silently accepted.
    #[test]
    fn release_contracts_require_specialized_roots() -> Result<(), super::GateError> {
        let fixture =
            release_contract_fixture(successful_lower_submission(), "ret i32 -1073741802", "");
        let missing_cancel = fixture.replace(ACTIVE_CANCEL_CALLBACK, "fixture::missing_cancel");
        let missing_cancel = IrModule::parse(&missing_cancel)?.analyze_release()?;
        require(
            missing_cancel
                .violations
                .iter()
                .any(|violation| violation.category == "callback protocol"),
            "missing active-cancel callback root was accepted",
        )?;

        let missing_publish = fixture.replace(DURABLE_PUBLISH_ROOT, "fixture::missing_publish");
        let missing_publish = IrModule::parse(&missing_publish)?.analyze_release()?;
        require(
            missing_publish
                .violations
                .iter()
                .any(|violation| violation.category == "post-commit allocation"),
            "missing durable-publication root was accepted",
        )
    }

    /// Durable publication may move and release prepared values but cannot allocate or construct
    /// mutable CNG state.
    ///
    /// # Errors
    ///
    /// Returns an error if allocator reachability from durable publication is not rejected.
    #[test]
    fn durable_publication_rejects_allocator_reachability() -> Result<(), super::GateError> {
        let fixture = release_contract_fixture(
            successful_lower_submission(),
            "ret i32 -1073741802",
            "  %allocation = call ptr @ExAllocatePool2(i64 64, i64 32, i32 1)",
        );
        let report = IrModule::parse(&fixture)?.analyze_release()?;
        require(
            report
                .violations
                .iter()
                .any(|violation| violation.category == "post-commit allocation"),
            "durable publication allocator path was accepted",
        )
    }
}

//! Explicit, read-only diagnostics for recorded driver artifacts and host state.
#![forbid(unsafe_code)]

extern crate alloc;

mod artifact;
mod completion;
mod extent;
mod pe;

use alloc::collections::BTreeMap;
use serde_json::{Value, json};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
};

/// Reports terminal CLI failures without hiding a checksum mismatch in a success exit status.
fn main() -> ExitCode {
    match execute(env::args().skip(1).collect()) {
        Ok(report) => {
            let success = report
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            println!("{report:#}");
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("{}", json!({"success": false, "error": error.to_string()}));
            ExitCode::FAILURE
        }
    }
}

/// Executes one diagnostic against explicit inputs; no lifecycle or storage mutation is issued.
///
/// # Errors
/// Returns input, artifact, parse, or native query failures.
fn execute(arguments: Vec<String>) -> io::Result<Value> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or_else(usage)?;
    if matches!(command.as_str(), "--help" | "help" | "-h") {
        return Ok(json!({"usage": usage().to_string(), "success": true}));
    }
    let arguments: Vec<_> = arguments.collect();
    if arguments
        .iter()
        .any(|item| item == "--help" || item == "-h")
    {
        return Ok(json!({"usage": usage().to_string(), "success": true}));
    }
    let mut input = None;
    let mut options = BTreeMap::<String, Vec<String>>::new();
    let mut words = arguments.into_iter();
    while let Some(word) = words.next() {
        if word.starts_with("--") {
            let value = words.next().ok_or_else(usage)?;
            options.entry(word).or_default().push(value);
        } else if input.replace(word).is_some() {
            return Err(usage());
        }
    }
    let permitted: &[&str] = match command.as_str() {
        "host" | "volume" => &[],
        "service" => &["--name"],
        "stack" => &["--limit", "--rva"],
        "completion" => &["--max-blocks"],
        "extent" => &["--superblock", "--block", "--inode", "--generation"],
        "waits" => &["--limit", "--match", "--encoding"],
        _ => return Err(usage()),
    };
    if options.keys().any(|key| !permitted.contains(&key.as_str()))
        || options
            .iter()
            .any(|(key, values)| values.len() != 1 && key != "--match" && key != "--rva")
    {
        return Err(usage());
    }
    if matches!(command.as_str(), "host" | "service" | "extent") && input.is_some() {
        return Err(usage());
    }
    let required_input = || input.as_deref().ok_or_else(usage);
    let option = |name: &str| {
        options
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    };
    match command.as_str() {
        "host" => Ok(host_tools()),
        "service" => service(option("--name").unwrap_or("ext4win")),
        "volume" => volume(required_input()?),
        "stack" | "completion" => {
            let kinds: &[&str] = if command == "stack" {
                &["sys", "map"]
            } else {
                &["sys", "map", "ir"]
            };
            let snapshot = artifact::Snapshot::read(Path::new(required_input()?), kinds)?;
            let mut report = if command == "stack" {
                let map = text(snapshot.bytes("map")?)?;
                let frames = pe::frames(snapshot.bytes("sys")?, map)?;
                let limit = positive(option("--limit").unwrap_or("20"))?;
                let mut addresses = Vec::new();
                for rva in options.get("--rva").into_iter().flatten() {
                    let rva = number(rva)?;
                    let frame = frames
                        .iter()
                        .find(|frame| frame.begin <= rva && rva < frame.end);
                    addresses.push(json!({"rva": rva, "frame": frame.map(pe::Frame::report),
                        "offset_in_function": frame.and_then(|frame| rva.checked_sub(frame.begin))}));
                }
                json!({"function_count": frames.len(), "largest_frames": frames.iter().take(limit).map(pe::Frame::report).collect::<Vec<_>>(), "addresses": addresses,
                    "scope": "Fixed prolog frames only; excludes return addresses, callees, dynamic allocation and interrupts."})
            } else {
                completion::check(
                    text(snapshot.bytes("ir")?)?,
                    positive(option("--max-blocks").unwrap_or("64"))?,
                )?
            };
            let object = report
                .as_object_mut()
                .ok_or_else(|| invalid("non-object analysis report"))?;
            object.insert("artifact_id".into(), json!(snapshot.identity));
            object.insert("recorded_source_sha256".into(), json!(snapshot.source));
            object.insert("artifact_sha256".into(), json!(snapshot.digests));
            object.insert("success".into(), json!(true));
            Ok(report)
        }
        "extent" => {
            let superblock = fs::read(option("--superblock").ok_or_else(usage)?)?;
            let block = fs::read(option("--block").ok_or_else(usage)?)?;
            let inode = number(option("--inode").ok_or_else(usage)?)?;
            let generation = number(option("--generation").ok_or_else(usage)?)?;
            let mut report = extent::check(&superblock, inode, generation, &block)?;
            let fields = report
                .as_object_mut()
                .ok_or_else(|| invalid("non-object checksum report"))?;
            fields.insert(
                "superblock_sha256".into(),
                json!(artifact::digest(&superblock)),
            );
            fields.insert("block_sha256".into(), json!(artifact::digest(&block)));
            Ok(report)
        }
        "waits" => {
            if !matches!(
                option("--encoding").unwrap_or("utf-8"),
                "utf-8" | "utf8" | "utf-16" | "utf-16le" | "ascii"
            ) {
                return Err(invalid(
                    "supported encodings: utf-8, utf-16, utf-16le, ascii",
                ));
            }
            let bytes = fs::read(required_input()?)?;
            let encoding = option("--encoding").unwrap_or("utf-8");
            let content = if encoding.starts_with("utf-16") {
                if bytes.len() % 2 != 0 {
                    return Err(invalid("truncated UTF-16 log"));
                }
                let (bytes, big_endian) = if encoding == "utf-16" {
                    match bytes.as_slice().split_at_checked(2) {
                        Some(([0xff, 0xfe], tail)) => (tail, false),
                        Some(([0xfe, 0xff], tail)) => (tail, true),
                        _ => return Err(invalid("UTF-16 log requires a byte-order mark")),
                    }
                } else {
                    (bytes.as_slice(), false)
                };
                let units: Vec<_> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| {
                        if big_endian {
                            u16::from_be_bytes(*pair)
                        } else {
                            u16::from_le_bytes(*pair)
                        }
                    })
                    .collect();
                String::from_utf16(&units).map_err(io::Error::other)?
            } else {
                if encoding == "ascii" && !bytes.is_ascii() {
                    return Err(invalid("non-ASCII byte in ASCII log"));
                }
                String::from_utf8(bytes).map_err(io::Error::other)?
            };
            let defaults = vec![
                "ext4win!".to_owned(),
                "FltpPerformPost".to_owned(),
                "FltpQueryInformation".to_owned(),
                "CcCopyRead".to_owned(),
                "CcWaitFor".to_owned(),
                "FsRtlCheckOplock".to_owned(),
            ];
            waits(
                &content,
                options.get("--match").unwrap_or(&defaults),
                positive(option("--limit").unwrap_or("20"))?,
            )
        }
        _ => Err(usage()),
    }
}

/// Returns the explicit command surface.
fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "cargo diagnose <host|service [--name NAME]|volume PATH|stack BUNDLE [--limit N] [--rva RVA]|completion BUNDLE [--max-blocks N]|extent --superblock FILE --block FILE --inode N --generation N|waits LOG [--match TEXT] [--limit N] [--encoding utf-8]>",
    )
}

/// Constructs a terminal malformed-input diagnostic.
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Decodes a decimal or hexadecimal unsigned input.
/// # Errors
/// Returns an error for malformed or overflowing input.
fn number(value: &str) -> io::Result<u64> {
    let result = if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    result.map_err(io::Error::other)
}

/// Decodes a positive resource budget.
/// # Errors
/// Returns an error for zero or an out-of-range budget.
fn positive(value: &str) -> io::Result<usize> {
    let value = usize::try_from(number(value)?).map_err(io::Error::other)?;
    if value == 0 {
        Err(invalid("expected a positive integer"))
    } else {
        Ok(value)
    }
}

/// Decodes strict UTF-8 artifact text.
/// # Errors
/// Returns an error when bytes are not UTF-8.
fn text(bytes: &[u8]) -> io::Result<&str> {
    core::str::from_utf8(bytes).map_err(io::Error::other)
}

/// Extracts complete matching thread sections and reports truncation separately.
/// # Errors
/// Returns an error for an empty match or zero budget.
fn waits(content: &str, terms: &[String], limit: usize) -> io::Result<Value> {
    if limit == 0 || terms.is_empty() || terms.iter().any(String::is_empty) {
        return Err(invalid(
            "positive section limit and nonempty match terms are required",
        ));
    }
    let mut sections = Vec::<String>::new();
    for line in content.split_inclusive('\n') {
        if line.trim_start().starts_with("THREAD ") || line.trim_start().starts_with("THREAD\t") {
            sections.push(String::new());
        }
        if let Some(section) = sections.last_mut() {
            section.push_str(line);
        }
    }
    let matches: Vec<_> = sections
        .iter()
        .filter(|section| terms.iter().any(|term| section.contains(term)))
        .collect();
    Ok(
        json!({"success": true, "thread_sections": sections.len(), "matching_sections": matches.len(), "truncated": matches.len() > limit,
        "sections": matches.into_iter().take(limit).collect::<Vec<_>>(), "debugger_quit_observed": content.contains("quit:")}),
    )
}

/// Inventories executables without launching them or changing the environment.
fn host_tools() -> Value {
    let variables = [
        "CC",
        "CXX",
        "RUSTFLAGS",
        "RUSTC_LINKER",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER",
        "LIBCLANG_PATH",
        "WDKContentRoot",
    ];
    let environment: BTreeMap<_, _> = variables
        .into_iter()
        .map(|name| (name, env::var(name).ok()))
        .collect();
    let names = [
        "cargo",
        "rustc",
        "cl",
        "clang-cl",
        "link",
        "lld-link",
        "llvm-readobj",
        "llvm-objdump",
        "llvm-symbolizer",
        "cdb",
        "kd",
        "wsl",
    ];
    let paths: Vec<PathBuf> = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect())
        .unwrap_or_default();
    let tools: BTreeMap<_, _> = names
        .into_iter()
        .map(|name| {
            let executable = if cfg!(windows) {
                format!("{name}.exe")
            } else {
                name.to_owned()
            };
            (
                name,
                paths
                    .iter()
                    .map(|path| path.join(&executable))
                    .find(|path| path.is_file()),
            )
        })
        .collect();
    let mut installed = Vec::new();
    for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(base) = env::var_os(variable) {
            let base = PathBuf::from(base);
            for name in names {
                let executable = base.join("LLVM/bin").join(format!("{name}.exe"));
                if executable.is_file() {
                    installed.push(executable);
                }
            }
            if let Ok(architectures) = fs::read_dir(base.join("Windows Kits/10/Debuggers")) {
                for directory in architectures.flatten() {
                    for name in ["cdb.exe", "kd.exe"] {
                        let executable = directory.path().join(name);
                        if executable.is_file() {
                            installed.push(executable);
                        }
                    }
                }
            }
        }
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "host-only diagnostic path sorting has no kernel allocation or panic constraint; PathBuf ordering is total"
    )]
    installed.sort();
    installed.dedup();
    json!({"success": true, "platform": env::consts::OS, "build_environment": environment, "path_tools": tools, "installed_tools": installed})
}

/// Queries the configured service image, without asserting what Windows loaded.
/// # Errors
/// Returns registry, image, or unsupported-host failures.
fn service(name: &str) -> io::Result<Value> {
    #[cfg(windows)]
    {
        let configuration = windows_host::service_configuration(name)?;
        if !matches!(configuration.kind, 1 | 2) {
            return Err(invalid("expected a kernel or filesystem driver"));
        }
        let path = windows_host::driver_path(&configuration.image)?;
        let bytes = fs::read(&path)?;
        Ok(
            json!({"success": true, "service": name, "configured_image": path, "sha256": artifact::digest(&bytes), "scope": "Configured service image on disk; loaded kernel image is unverified."}),
        )
    }
    #[cfg(not(windows))]
    {
        let _name = name;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "service diagnostic requires Windows",
        ))
    }
}

/// Reads native volume information with synchronous queries that may wait inside the driver.
/// # Errors
/// Returns opening, query, release, or unsupported-host failures.
fn volume(path: &str) -> io::Result<Value> {
    #[cfg(windows)]
    {
        let queries = windows_host::volume_information(Path::new(path))?;
        let success = queries.iter().all(|query| query.status >= 0);
        let queries: Vec<_> = queries.into_iter().map(|query| json!({"class": query.name, "class_number": query.number,
            "ntstatus": format!("0x{:08x}", query.status.cast_unsigned()), "success": query.status >= 0,
            "returned_bytes": query.data.len(), "data_hex": artifact::hex(&query.data), "milliseconds": query.milliseconds})).collect();
        Ok(json!({"success": success, "path": path, "queries": queries}))
    }
    #[cfg(not(windows))]
    {
        let _path = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "volume diagnostic requires Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A bounded extraction reports omitted matches and keeps complete thread records.
    /// # Errors
    /// Returns unexpected extraction errors.
    /// # Panics
    /// Panics if section boundaries, counts, or CLI validation regress.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions intentionally fail contract tests after fallible preparation"
    )]
    fn bounded_waits_and_inputs() -> io::Result<()> {
        let report = waits(
            "header\n THREAD a\n ext4win!one\n THREAD b\n other\n THREAD c\n ext4win!two\nquit:\n",
            &["ext4win!".into()],
            1,
        )?;
        assert_eq!(report.get("matching_sections"), Some(&json!(2)));
        assert_eq!(report.get("thread_sections"), Some(&json!(3)));
        assert_eq!(report.get("truncated"), Some(&json!(true)));
        assert!(
            execute(vec![
                "stack".into(),
                "bundle".into(),
                "--limit".into(),
                "0".into()
            ])
            .is_err()
        );
        assert!(execute(vec!["volume".into()]).is_err());
        Ok(())
    }
}

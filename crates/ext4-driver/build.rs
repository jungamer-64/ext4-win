//! Build script for the native ext4 Windows file system driver.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::error::Error;
use std::{ffi::OsString, fs, io, path::PathBuf};

/// Environment variable carrying the one-build production artifact identity.
const ARTIFACT_ID_ENVIRONMENT: &str = "EXT4WIN_ARTIFACT_ID";

/// Sentinel used by ordinary developer builds that cannot pass the production artifact gate.
const UNVERIFIED_ARTIFACT_ID: &str = "00000000000000000000000000000000";

/// Linker-visible symbol that keeps the artifact marker in the final PE image.
const ARTIFACT_ID_SYMBOL: &str = "EXT4WIN_PRODUCTION_ARTIFACT_ID";

/// File generated into Cargo's build output and embedded verbatim in the driver image.
const ARTIFACT_ID_RECORD_FILE: &str = "artifact-identity.bin";

/// Repository-owned source for the named control-device lifecycle boundary.
const LIFECYCLE_CONTROL_CONTRACT: &str = "lifecycle-control-v1.txt";

/// Generated Rust constants consumed by the kernel boundary.
const LIFECYCLE_CONTROL_RUST: &str = "lifecycle-control-v1.rs";

/// Prefix shared with the production reachability verifier.
const ARTIFACT_ID_MARKER: &str = "EXT4WIN_ARTIFACT_ID=";

fn main() -> Result<(), Box<dyn Error>> {
    const SECURITY_CAPTURE_SOURCE: &str = "native/security_capture.c";
    const DATA_TRANSFER_SOURCE: &str = "native/data_transfer.c";
    const CANCEL_SOURCE: &str = "native/cancel.c";
    const STREAM_CONTEXT_SOURCE: &str = "native/stream_context.c";

    println!("cargo:rerun-if-changed={SECURITY_CAPTURE_SOURCE}");
    println!("cargo:rerun-if-changed={DATA_TRANSFER_SOURCE}");
    println!("cargo:rerun-if-changed={CANCEL_SOURCE}");
    println!("cargo:rerun-if-changed={STREAM_CONTEXT_SOURCE}");
    println!("cargo:rerun-if-changed={LIFECYCLE_CONTROL_CONTRACT}");
    println!("cargo:rerun-if-env-changed={ARTIFACT_ID_ENVIRONMENT}");

    let artifact_id = production_artifact_id()?;
    println!("cargo:rustc-env={ARTIFACT_ID_ENVIRONMENT}={artifact_id}");
    write_artifact_identity_record(&artifact_id)?;
    write_lifecycle_control_contract()?;

    let config = wdk_build::Config::from_env_auto()?;
    config.configure_binary_build()?;

    let is_msvc = std::env::var_os("CARGO_CFG_TARGET_ENV").is_some_and(|target| target == "msvc");
    let mut native = cc::Build::new();
    for (name, value) in config.preprocessor_definitions() {
        // MSVC's /kernel switch defines this reserved implementation macro itself.
        if !(is_msvc && name == "_KERNEL_MODE") {
            native.define(&name, value.as_deref());
        }
    }
    native
        .includes(config.include_paths()?)
        .file(SECURITY_CAPTURE_SOURCE)
        .file(DATA_TRANSFER_SOURCE)
        .file(CANCEL_SOURCE)
        .file(STREAM_CONTEXT_SOURCE);

    if is_msvc {
        native.flag("/kernel").flag("/W4").flag("/WX");
        let map_path = package_link_map_path()?;
        let map_parent = map_path
            .parent()
            .ok_or_else(|| io::Error::other("the ext4win link-map path has no parent directory"))?;
        fs::create_dir_all(map_parent)?;
        println!("cargo:rustc-link-arg=/MAP:{}", map_path.display());
        println!("cargo:rustc-link-arg=/INCLUDE:{ARTIFACT_ID_SYMBOL}");
    }

    native.compile("ext4win_security_capture");
    Ok(())
}

/// Generates the one Rust projection of the driver-load control contract.
///
/// # Errors
///
/// Returns an input or I/O error when the checked-in contract is incomplete, malformed, or cannot
/// be written to Cargo's build output.
fn write_lifecycle_control_contract() -> Result<(), io::Error> {
    let records = read_contract_records(LIFECYCLE_CONTROL_CONTRACT)?;
    if required_record(&records, "contract_version")? != "1" {
        return Err(invalid_contract(
            "unsupported lifecycle control contract version",
        ));
    }
    let native_name = required_record(&records, "nt_device_name")?;
    // Keep the control device in the device-object directory, separate from the filesystem
    // driver object that the I/O manager names from the service before entering DriverEntry.
    if !native_name
        .strip_prefix(r"\Device\")
        .is_some_and(|name| !name.is_empty() && !name.contains('\\'))
    {
        return Err(invalid_contract(
            "lifecycle control device must be a direct child of the Device object directory",
        ));
    }
    let nt_device_name = unicode_constant("CONTROL_DEVICE_NT_NAME", native_name)?;
    let dos_device_name = unicode_constant(
        "CONTROL_DEVICE_DOS_NAME",
        required_record(&records, "dos_device_name")?,
    )?;
    let device_sddl = unicode_constant(
        "CONTROL_DEVICE_SDDL",
        required_record(&records, "device_sddl")?,
    )?;
    let guid = parse_guid(required_record(&records, "device_class_guid")?)?;
    let ioctl = parse_hex_u32(required_record(&records, "prepare_unload_ioctl")?)?;

    let generated = format!(
        "{nt_device_name}\n{dos_device_name}\n{device_sddl}\n\
         /// Custom device-setup class used only for the secured ext4win control device.\n\
         pub(crate) static CONTROL_DEVICE_CLASS_GUID: wdk_sys::GUID = wdk_sys::GUID {{\n\
             Data1: 0x{data1:08X},\n\
             Data2: 0x{data2:04X},\n\
             Data3: 0x{data3:04X},\n\
             Data4: [{data4}],\n\
         }};\n\
         /// Write-authorized, payload-free request that consumes filesystem registration.\n\
         pub(crate) const PREPARE_UNLOAD_IOCTL: wdk_sys::ULONG = 0x{ioctl:08X};\n",
        data1 = guid.0,
        data2 = guid.1,
        data3 = guid.2,
        data4 = render_u8_array(&guid.3),
    );
    let out_directory =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Cargo did not provide OUT_DIR")
        })?);
    fs::write(out_directory.join(LIFECYCLE_CONTROL_RUST), generated)
}

/// Reads one unique, nonempty key-value record set.
/// # Errors
///
/// Returns an I/O error when the file cannot be read or an input error for malformed or duplicate
/// records.
fn read_contract_records(path: &str) -> Result<BTreeMap<String, String>, io::Error> {
    let mut records = BTreeMap::new();
    for line in fs::read_to_string(path)?.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(invalid_contract("lifecycle control record lacks '='"));
        };
        if key.is_empty()
            || value.is_empty()
            || records.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(invalid_contract(
                "lifecycle control record is empty or duplicated",
            ));
        }
    }
    Ok(records)
}

/// Selects one required lifecycle-control value.
/// # Errors
///
/// Returns an input error when `key` is absent.
fn required_record<'records>(
    records: &'records BTreeMap<String, String>,
    key: &str,
) -> Result<&'records str, io::Error> {
    records
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| invalid_contract("lifecycle control contract is missing a required record"))
}

/// Generates a terminated UTF-16 array plus its checked `UNICODE_STRING` byte length.
/// # Errors
///
/// Returns an input error when the value contains NUL or exceeds `UNICODE_STRING` lengths.
fn unicode_constant(name: &str, value: &str) -> Result<String, io::Error> {
    if value.chars().any(|character| character == '\0') {
        return Err(invalid_contract(
            "lifecycle control Unicode value contains NUL",
        ));
    }
    let mut units = value.encode_utf16().collect::<Vec<_>>();
    let byte_length = units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| invalid_contract("lifecycle control Unicode value is too long"))?;
    units.push(0);
    let maximum_byte_length = units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| invalid_contract("lifecycle control Unicode value is too long"))?;
    Ok(format!(
        "/// Generated, NUL-terminated lifecycle-control string.\n\
         pub(crate) static {name}: [u16; {length}] = [{units}];\n\
         /// Byte length excluding the generated terminator.\n\
         pub(crate) const {name}_BYTE_LENGTH: wdk_sys::USHORT = {byte_length};\n\
         /// Buffer capacity including the generated terminator.\n\
         pub(crate) const {name}_MAXIMUM_BYTE_LENGTH: wdk_sys::USHORT = {maximum_byte_length};",
        length = units.len(),
        units = render_u16_array(&units),
    ))
}

/// Parses one canonical hexadecimal `u32` record.
/// # Errors
///
/// Returns an input error when the prefix or hexadecimal payload is malformed.
fn parse_hex_u32(value: &str) -> Result<u32, io::Error> {
    let Some(digits) = value.strip_prefix("0x") else {
        return Err(invalid_contract(
            "lifecycle control integer lacks 0x prefix",
        ));
    };
    u32::from_str_radix(digits, 16)
        .map_err(|_| invalid_contract("lifecycle control integer is malformed"))
}

/// Parses the canonical GUID spelling into native fields.
/// # Errors
///
/// Returns an input error when the GUID shape, field widths, or digits are malformed.
fn parse_guid(value: &str) -> Result<(u32, u16, u16, [u8; 8]), io::Error> {
    let mut fields = value.split('-');
    let data1 = parse_fixed_hex(fields.next(), 8)?;
    let data2 = u16::try_from(parse_fixed_hex(fields.next(), 4)?)
        .map_err(|_| invalid_contract("lifecycle control GUID field is out of range"))?;
    let data3 = u16::try_from(parse_fixed_hex(fields.next(), 4)?)
        .map_err(|_| invalid_contract("lifecycle control GUID field is out of range"))?;
    let Some(data4_high) = fields.next() else {
        return Err(invalid_contract("lifecycle control GUID is incomplete"));
    };
    let Some(data4_low) = fields.next() else {
        return Err(invalid_contract("lifecycle control GUID is incomplete"));
    };
    if fields.next().is_some() || data4_high.len() != 4 || data4_low.len() != 12 {
        return Err(invalid_contract("lifecycle control GUID shape is invalid"));
    }
    let high = u16::try_from(parse_fixed_hex(Some(data4_high), 4)?)
        .map_err(|_| invalid_contract("lifecycle control GUID field is out of range"))?;
    let low = parse_fixed_hex_u64(data4_low, 12)?;
    let mut data4 = [0_u8; 8];
    let bytes = high
        .to_be_bytes()
        .into_iter()
        .chain(low.to_be_bytes().into_iter().skip(2));
    for (destination, byte) in data4.iter_mut().zip(bytes) {
        *destination = byte;
    }
    Ok((data1, data2, data3, data4))
}

/// Parses one exact-width hexadecimal GUID field.
/// # Errors
///
/// Returns an input error when the field width or digits are malformed.
fn parse_fixed_hex(value: Option<&str>, width: usize) -> Result<u32, io::Error> {
    let Some(value) = value.filter(|value| value.len() == width) else {
        return Err(invalid_contract(
            "lifecycle control GUID field has invalid width",
        ));
    };
    u32::from_str_radix(value, 16)
        .map_err(|_| invalid_contract("lifecycle control GUID contains non-hex digits"))
}

/// Parses one exact-width hexadecimal GUID tail field.
/// # Errors
///
/// Returns an input error when the field width or digits are malformed.
fn parse_fixed_hex_u64(value: &str, width: usize) -> Result<u64, io::Error> {
    if value.len() != width {
        return Err(invalid_contract(
            "lifecycle control GUID field has invalid width",
        ));
    }
    u64::from_str_radix(value, 16)
        .map_err(|_| invalid_contract("lifecycle control GUID contains non-hex digits"))
}

/// Renders generated `u16` array elements without a second semantic parser.
fn render_u16_array(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:04X}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders generated `u8` array elements without a second semantic parser.
fn render_u8_array(values: &[u8]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:02X}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Builds one stable invalid-data error for the checked-in lifecycle contract.
fn invalid_contract(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Writes the exact bytes later embedded at the linker-visible identity symbol.
///
/// # Errors
///
/// Returns an environment or I/O error when Cargo's output directory cannot be resolved or
/// written.
fn write_artifact_identity_record(artifact_id: &str) -> Result<(), io::Error> {
    let out_directory =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Cargo did not provide OUT_DIR")
        })?);
    let mut record = String::from(ARTIFACT_ID_MARKER);
    record.push_str(artifact_id);
    fs::write(
        out_directory.join(ARTIFACT_ID_RECORD_FILE),
        record.as_bytes(),
    )
}

/// Validates the externally supplied artifact identity or selects the fail-closed sentinel.
///
/// # Errors
///
/// Returns an input error when a supplied identity is not exactly 32 nonzero hexadecimal digits.
fn production_artifact_id() -> Result<String, io::Error> {
    let Some(value) = std::env::var_os(ARTIFACT_ID_ENVIRONMENT) else {
        return Ok(UNVERIFIED_ARTIFACT_ID.to_owned());
    };
    let value = value.into_string().map_err(|_: OsString| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ARTIFACT_ID_ENVIRONMENT} is not valid Unicode"),
        )
    })?;
    if value.len() != UNVERIFIED_ARTIFACT_ID.len()
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value == UNVERIFIED_ARTIFACT_ID
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{ARTIFACT_ID_ENVIRONMENT} must be 32 hexadecimal digits and cannot be all zero"
            ),
        ));
    }
    Ok(value)
}

/// Resolves the fixed link-map path consumed by `cargo-wdk` packaging.
///
/// # Errors
///
/// Returns an environment or layout error when Cargo's profile directory cannot be identified.
fn package_link_map_path() -> Result<PathBuf, io::Error> {
    let out_directory =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Cargo did not provide OUT_DIR")
        })?);
    let build_directory = out_directory
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .ok_or_else(|| io::Error::other("OUT_DIR is not below Cargo's build directory"))?;
    let profile_directory = build_directory
        .parent()
        .ok_or_else(|| io::Error::other("Cargo's build directory has no profile parent"))?;
    Ok(profile_directory.join("deps").join("ext4win.map"))
}

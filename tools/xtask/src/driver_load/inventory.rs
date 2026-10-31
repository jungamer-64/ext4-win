//! PnPUtil XML observations; package admission still requires native mapping and byte identity.
use crate::TaskResult;
use alloc::borrow::Cow;
use quick_xml::de::Deserializer;
use serde::Deserialize;
use std::io;

/// An ext4-win inventory entry with exactly one expected SYS, without lifecycle authority.
#[derive(Debug)]
pub(super) struct Package {
    /// Published OEM identity used for independent DriverStore selection.
    pub(super) oem: String,
}

/// The root name distinguishes an empty inventory from an unrelated XML document.
#[derive(Debug, Deserialize)]
enum InventoryDocument {
    /// Structured output of the successful PnPUtil inventory command.
    PnpUtil(DriverInventory),
}

/// External inventory envelope; other PnPUtil metadata does not select packages.
#[derive(Debug, Deserialize)]
struct DriverInventory {
    /// Repeated driver records, absent when the inventory is empty.
    #[serde(rename = "Driver", default)]
    drivers: Vec<DriverRecord>,
}

/// External package identity and the associated files reported by PnPUtil.
#[derive(Debug, Deserialize)]
struct DriverRecord {
    /// Published INF name is an XML attribute rather than element content.
    #[serde(rename = "@DriverName")]
    oem: String,
    /// Original package INF filename.
    #[serde(rename = "OriginalName")]
    original: String,
    /// Package provider from the installed INF.
    #[serde(rename = "ProviderName")]
    provider: String,
    /// Unrelated packages need not contain any listed driver files.
    #[serde(rename = "Files", default)]
    files: DriverFiles,
}

/// External file-list envelope, including the valid empty representation.
#[derive(Debug, Default, Deserialize)]
struct DriverFiles {
    /// Files are represented by repeated elements, even for a single file.
    #[serde(rename = "File", default)]
    entries: Vec<DriverFile>,
}

/// Only a file's name participates in inventory selection.
#[derive(Debug, Deserialize)]
struct DriverFile {
    /// Exact XML attribute value, after entity and character decoding.
    #[serde(rename = "@Name")]
    name: String,
}

/// Byte order established by the inventory's UTF-16 byte-order mark.
#[derive(Clone, Copy)]
enum Utf16ByteOrder {
    /// Least-significant byte precedes the most-significant byte.
    Little,
    /// Most-significant byte precedes the least-significant byte.
    Big,
}

impl Utf16ByteOrder {
    /// Converts one complete external code unit before Unicode validation.
    fn decode(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }
}

/// Decodes the Unicode encodings used by the Windows inventory-file boundary.
/// # Errors
/// Returns malformed UTF-8, unpaired UTF-16 surrogates or incomplete UTF-16 code units.
fn inventory_text(bytes: &[u8]) -> TaskResult<Cow<'_, str>> {
    let (bytes, order) = if let Some(body) = bytes.strip_prefix(&[0xff, 0xfe]) {
        (body, Utf16ByteOrder::Little)
    } else if let Some(body) = bytes.strip_prefix(&[0xfe, 0xff]) {
        (body, Utf16ByteOrder::Big)
    } else {
        return Ok(Cow::Borrowed(core::str::from_utf8(
            bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes),
        )?));
    };
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(
            io::Error::other("DriverStore inventory ends inside a UTF-16 code unit").into(),
        );
    }
    let units: Vec<_> = pairs.iter().map(|&unit| order.decode(unit)).collect();
    Ok(Cow::Owned(String::from_utf16(&units)?))
}

/// Parses one complete inventory without executing a provider or resolving external entities.
/// UTF-8 and BOM-marked UTF-16 observations share the same package-selection contract.
/// # Errors
/// Returns malformed XML, wrong roots, trailing documents, missing identity fields or selected
/// packages whose OEM name or expected SYS multiplicity is invalid. Failure never means absence.
pub(super) fn packages(bytes: &[u8]) -> TaskResult<Vec<Package>> {
    let xml = inventory_text(bytes)?;
    let mut deserializer = Deserializer::from_str(&xml);
    let mut documents = Vec::<InventoryDocument>::deserialize(&mut deserializer)?;
    if documents.len() != 1 || !deserializer.is_empty() {
        return Err(
            io::Error::other("DriverStore inventory must contain exactly one document").into(),
        );
    }
    let Some(InventoryDocument::PnpUtil(inventory)) = documents.pop() else {
        return Err(io::Error::other("DriverStore inventory document is absent").into());
    };
    let mut selected = Vec::new();
    for record in inventory.drivers {
        if !record.original.eq_ignore_ascii_case("ext4win.inf")
            || !record.provider.eq_ignore_ascii_case("ext4-win")
        {
            continue;
        }
        if !record
            .oem
            .strip_prefix("oem")
            .and_then(|name| name.strip_suffix(".inf"))
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(
                io::Error::other("DriverStore inventory has an invalid OEM INF name").into(),
            );
        }
        if record
            .files
            .entries
            .iter()
            .filter(|file| file.name.eq_ignore_ascii_case("ext4win.sys"))
            .count()
            != 1
        {
            return Err(io::Error::other(
                "structured DriverStore inventory does not identify exactly one SYS",
            )
            .into());
        }
        selected.push(Package { oem: record.oem });
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent XML fixtures exercise provider selection, attributes, lists and encodings.
    /// # Errors
    /// Returns unexpected parsing or encoding failures.
    /// # Panics
    /// Fails if a complete observation loses its selected OEM identity or ambiguity.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare independent XML observations after fallible parsing"
    )]
    fn structured_package_observations() -> TaskResult<()> {
        let xml = r#"<?xml version="1.0"?>
<PnpUtil Version="10.0.28000" Command="/enum-drivers /files /format xml">
  <Driver DriverName="oem4.inf">
    <OriginalName>other.inf</OriginalName><ProviderName>Other &amp; Co</ProviderName>
  </Driver>
  <Driver DriverName="oem5.inf">
    <OriginalName>ext4win.inf</OriginalName><ProviderName>Other</ProviderName>
  </Driver>
  <Driver DriverName="oem6.inf">
    <OriginalName>other.inf</OriginalName><ProviderName>ext4-win</ProviderName>
  </Driver>
  <Driver DriverName="oem12.inf">
    <OriginalName>EXT4WIN.INF</OriginalName><ProviderName>EXT4-WIN</ProviderName>
    <ClassName>System</ClassName>
    <Files><File Name="EXT4WIN.SYS"/><File Name="notice-&amp;-日本語.txt"/></Files>
  </Driver>
</PnpUtil>
<!-- end of inventory -->
"#;
        let selected = packages(xml.as_bytes())?;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected.first().map(|p| p.oem.as_str()), Some("oem12.inf"));
        for little_endian in [true, false] {
            let mut encoded = if little_endian {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            for unit in xml.encode_utf16() {
                encoded.extend_from_slice(&if little_endian {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            let selected = packages(&encoded)?;
            assert_eq!(selected.first().map(|p| p.oem.as_str()), Some("oem12.inf"));
        }
        assert!(packages(b"<PnpUtil/>")?.is_empty());
        assert!(packages(b"\xef\xbb\xbf<PnpUtil/>\r\n")?.is_empty());
        let duplicated = xml.replace("</PnpUtil>", r#"<Driver DriverName="oem13.inf"><OriginalName>ext4win.inf</OriginalName><ProviderName>ext4-win</ProviderName><Files><File Name="ext4win.sys"/></Files></Driver></PnpUtil>"#);
        assert_eq!(packages(duplicated.as_bytes())?.len(), 2);
        Ok(())
    }

    /// A failed inventory cannot become evidence that no ext4-win package is installed.
    /// # Panics
    /// Fails if malformed structure or incomplete selected identity is accepted.
    #[test]
    fn invalid_observations_do_not_establish_absence() {
        for bytes in [
            &[0xff, 0xfe, 0x3c][..],
            &[0xff, 0xfe, 0, 0xd8][..],
            &[0xff][..],
        ] {
            assert!(packages(bytes).is_err());
        }
        for xml in [
            "",
            "<Wrong/>",
            "<PnpUtil>",
            "<PnpUtil/><PnpUtil/>",
            "<PnpUtil/><Wrong/>",
            "<PnpUtil/>trailing text",
            "<PnpUtil/><broken",
            r#"<PnpUtil><Driver DriverName="oem12.inf"><OriginalName>ext4win.inf</OriginalName></Driver></PnpUtil>"#,
            r#"<PnpUtil><Driver DriverName="oem12.inf"><OriginalName>ext4win.inf</OriginalName><ProviderName>ext4-win</ProviderName></Driver></PnpUtil>"#,
            r#"<PnpUtil><Driver DriverName="oem12.inf"><OriginalName>ext4win.inf</OriginalName><ProviderName>ext4-win</ProviderName><Files><File Name="ext4win.sys"/><File Name="EXT4WIN.SYS"/></Files></Driver></PnpUtil>"#,
            r#"<PnpUtil><Driver DriverName="../oem12.inf"><OriginalName>ext4win.inf</OriginalName><ProviderName>ext4-win</ProviderName><Files><File Name="ext4win.sys"/></Files></Driver></PnpUtil>"#,
            r#"<!DOCTYPE PnpUtil [<!ENTITY external SYSTEM "file:///not-an-inventory">]><PnpUtil>&external;</PnpUtil>"#,
        ] {
            assert!(packages(xml.as_bytes()).is_err(), "{xml}");
        }
    }
}

//! ext4 protection features.

pub(crate) mod crypto;
pub(crate) mod fscrypt;
pub(crate) mod verity;

#[cfg(test)]
use hkdf::Hkdf;
#[cfg(test)]
use sha2::{Digest, Sha256, Sha512};

#[cfg(test)]
use crate::{Error, Result};

/// Test-only cryptographic oracle shared by protection-domain unit tests.
///
/// Hash and HKDF calls use independent reference implementations. Reversible cipher calls are a
/// deterministic transport double because CNG compatibility vectors live at the driver boundary.
#[cfg(test)]
#[derive(Debug, Default)]
struct TestCryptographicOperation;

#[cfg(test)]
impl crypto::CryptographicOperation for TestCryptographicOperation {
    fn fill_random(&mut self, output: &mut [u8]) -> Result<()> {
        let mut value = 0_u8;
        for byte in output {
            *byte = value;
            value = value.wrapping_add(1);
        }
        Ok(())
    }

    fn hkdf_sha512(&mut self, key: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
        Hkdf::<Sha512>::new(None, key)
            .expand(info, output)
            .map_err(|_| Error::CryptographicFailure)
    }

    fn encrypt_aes_256_xts(
        &mut self,
        key: &[u8; 64],
        data_unit: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        reversible_transport(key, data_unit, buffer);
        Ok(())
    }

    fn decrypt_aes_256_xts(
        &mut self,
        key: &[u8; 64],
        data_unit: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        reversible_transport(key, data_unit, buffer);
        Ok(())
    }

    fn encrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], buffer: &mut [u8]) -> Result<()> {
        reversible_transport(key, 0, buffer);
        Ok(())
    }

    fn decrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], buffer: &mut [u8]) -> Result<()> {
        reversible_transport(key, 0, buffer);
        Ok(())
    }

    fn sha256(&mut self, input: &[u8]) -> Result<[u8; 32]> {
        let digest = Sha256::digest(input);
        let mut output = [0_u8; 32];
        for (destination, source) in output.iter_mut().zip(digest) {
            *destination = source;
        }
        Ok(output)
    }

    fn sha512(&mut self, input: &[u8]) -> Result<[u8; 64]> {
        let digest = Sha512::digest(input);
        let mut output = [0_u8; 64];
        for (destination, source) in output.iter_mut().zip(digest) {
            *destination = source;
        }
        Ok(output)
    }
}

/// Applies a deterministic involution for core tests that do not validate platform cipher bytes.
#[cfg(test)]
fn reversible_transport(key: &[u8], data_unit: u64, buffer: &mut [u8]) {
    for (byte, key_byte) in buffer.iter_mut().zip(key.iter().copied().cycle()) {
        *byte ^= key_byte;
    }
    for (byte, tweak_byte) in buffer
        .iter_mut()
        .zip(data_unit.to_le_bytes().into_iter().cycle())
    {
        *byte ^= tweak_byte;
    }
}

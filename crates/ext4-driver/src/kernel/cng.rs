//! Kernel CNG provider and operation-owned cryptographic objects.

use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{CryptographicOperation, Error, Result as Ext4Result};
use wdk_sys::{NT_SUCCESS, NTSTATUS, STATUS_INSUFFICIENT_RESOURCES};

use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;

/// NUL-terminated UTF-16 CNG identifier for the kernel XTS-AES provider.
static XTS_AES_ALGORITHM: [u16; 8] = [88, 84, 83, 45, 65, 69, 83, 0];
/// NUL-terminated UTF-16 CNG identifier for the AES provider.
static AES_ALGORITHM: [u16; 4] = [65, 69, 83, 0];
/// NUL-terminated UTF-16 CNG identifier for the HKDF provider.
static HKDF_ALGORITHM: [u16; 5] = [72, 75, 68, 70, 0];
/// NUL-terminated UTF-16 CNG identifier for the SHA-256 provider.
static SHA256_ALGORITHM: [u16; 7] = [83, 72, 65, 50, 53, 54, 0];
/// NUL-terminated UTF-16 CNG identifier for the SHA-512 provider.
static SHA512_ALGORITHM: [u16; 7] = [83, 72, 65, 53, 49, 50, 0];
/// NUL-terminated UTF-16 CNG property name for provider object length.
static OBJECT_LENGTH_PROPERTY: [u16; 13] =
    [79, 98, 106, 101, 99, 116, 76, 101, 110, 103, 116, 104, 0];
/// NUL-terminated UTF-16 CNG property name for hash digest length.
static HASH_LENGTH_PROPERTY: [u16; 17] = [
    72, 97, 115, 104, 68, 105, 103, 101, 115, 116, 76, 101, 110, 103, 116, 104, 0,
];
/// NUL-terminated UTF-16 CNG property name for cipher block length.
static BLOCK_LENGTH_PROPERTY: [u16; 12] = [66, 108, 111, 99, 107, 76, 101, 110, 103, 116, 104, 0];
/// NUL-terminated UTF-16 CNG property name for an XTS data-unit length.
static MESSAGE_BLOCK_LENGTH_PROPERTY: [u16; 19] = [
    77, 101, 115, 115, 97, 103, 101, 66, 108, 111, 99, 107, 76, 101, 110, 103, 116, 104, 0,
];
/// NUL-terminated UTF-16 CNG property name for a provider chaining mode.
static CHAINING_MODE_PROPERTY: [u16; 13] =
    [67, 104, 97, 105, 110, 105, 110, 103, 77, 111, 100, 101, 0];
/// NUL-terminated UTF-16 CNG chaining-mode value selecting ECB.
static CHAINING_MODE_ECB: [u16; 16] = [
    67, 104, 97, 105, 110, 105, 110, 103, 77, 111, 100, 101, 69, 67, 66, 0,
];
/// NUL-terminated UTF-16 CNG HKDF property selecting the underlying hash.
static HKDF_HASH_ALGORITHM_PROPERTY: [u16; 18] = [
    72, 107, 100, 102, 72, 97, 115, 104, 65, 108, 103, 111, 114, 105, 116, 104, 109, 0,
];
/// NUL-terminated UTF-16 CNG HKDF property supplying salt and finalizing extraction.
static HKDF_SALT_AND_FINALIZE_PROPERTY: [u16; 20] = [
    72, 107, 100, 102, 83, 97, 108, 116, 65, 110, 100, 70, 105, 110, 97, 108, 105, 122, 101, 0,
];

/// Ask CNG to use the system-preferred RNG without opening an algorithm handle.
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
/// Keep one hash object reusable after every successful `BCryptFinishHash`.
const BCRYPT_HASH_REUSABLE_FLAG: u32 = 0x0000_0020;
/// CNG parameter-buffer descriptor version.
const BCRYPT_BUFFER_VERSION: u32 = 0;
/// HKDF application-information parameter type.
const KDF_HKDF_INFO: u32 = 0x0000_0014;
/// AES block size required by fscrypt's XTS and CBC-CS3 profiles.
const AES_BLOCK_BYTES: usize = 16;
/// NTSTATUS returned by CNG when its internal provider allocation fails.
const STATUS_NO_MEMORY: NTSTATUS = i32::from_ne_bytes(0xC000_0017_u32.to_ne_bytes());

/// C-compatible single parameter passed to `BCryptKeyDerivation`.
#[repr(C)]
struct BCryptBuffer {
    /// Parameter byte length.
    buffer_bytes: u32,
    /// Parameter domain tag.
    buffer_type: u32,
    /// Caller-owned parameter bytes.
    buffer: *mut c_void,
}

/// C-compatible parameter list passed to `BCryptKeyDerivation`.
#[repr(C)]
struct BCryptBufferDesc {
    /// Descriptor ABI version.
    version: u32,
    /// Number of entries at `buffers`.
    buffer_count: u32,
    /// Caller-owned parameter array.
    buffers: *mut BCryptBuffer,
}

#[cfg_attr(not(test), link(name = "Cng"))]
#[cfg_attr(test, link(name = "Bcrypt"))]
unsafe extern "system" {
    fn BCryptOpenAlgorithmProvider(
        algorithm: *mut *mut c_void,
        algorithm_id: *const u16,
        implementation: *const u16,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptCloseAlgorithmProvider(algorithm: *mut c_void, flags: u32) -> NTSTATUS;
    fn BCryptGetProperty(
        object: *mut c_void,
        property: *const u16,
        output: *mut u8,
        output_bytes: u32,
        result_bytes: *mut u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptSetProperty(
        object: *mut c_void,
        property: *const u16,
        input: *mut u8,
        input_bytes: u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptGenRandom(
        algorithm: *mut c_void,
        buffer: *mut u8,
        buffer_len: u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptGenerateSymmetricKey(
        algorithm: *mut c_void,
        key: *mut *mut c_void,
        key_object: *mut u8,
        key_object_bytes: u32,
        secret: *mut u8,
        secret_bytes: u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptDestroyKey(key: *mut c_void) -> NTSTATUS;
    fn BCryptEncrypt(
        key: *mut c_void,
        input: *mut u8,
        input_bytes: u32,
        padding_info: *mut c_void,
        initialization_vector: *mut u8,
        initialization_vector_bytes: u32,
        output: *mut u8,
        output_bytes: u32,
        result_bytes: *mut u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptDecrypt(
        key: *mut c_void,
        input: *mut u8,
        input_bytes: u32,
        padding_info: *mut c_void,
        initialization_vector: *mut u8,
        initialization_vector_bytes: u32,
        output: *mut u8,
        output_bytes: u32,
        result_bytes: *mut u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptKeyDerivation(
        key: *mut c_void,
        parameters: *mut BCryptBufferDesc,
        output: *mut u8,
        output_bytes: u32,
        result_bytes: *mut u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptCreateHash(
        algorithm: *mut c_void,
        hash: *mut *mut c_void,
        hash_object: *mut u8,
        hash_object_bytes: u32,
        secret: *mut u8,
        secret_bytes: u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptHashData(hash: *mut c_void, input: *mut u8, input_bytes: u32, flags: u32) -> NTSTATUS;
    fn BCryptFinishHash(
        hash: *mut c_void,
        output: *mut u8,
        output_bytes: u32,
        flags: u32,
    ) -> NTSTATUS;
    fn BCryptDestroyHash(hash: *mut c_void) -> NTSTATUS;
}

/// Non-null CNG algorithm handle whose close authority remains mount-scoped.
#[derive(Clone, Copy)]
struct AlgorithmHandle(NonNull<c_void>);

impl AlgorithmHandle {
    /// Exposes the opaque handle only at the CNG call boundary.
    const fn as_raw(self) -> *mut c_void {
        self.0.as_ptr()
    }
}

// SAFETY: CNG algorithm handles are opaque kernel provider identities. They are opened and closed
// on the PASSIVE_LEVEL reactor, and operation calls are serialized by that same reactor thread.
unsafe impl Send for AlgorithmHandle {}

/// Mount-owned close authority for one algorithm provider.
struct OwnedAlgorithmHandle(AlgorithmHandle);

impl OwnedAlgorithmHandle {
    /// Opens one default CNG primitive provider at PASSIVE_LEVEL.
    /// # Errors
    ///
    /// Returns an error when CNG cannot open the provider or returns a null handle.
    fn open(identifier: &[u16]) -> DriverResult<Self> {
        let mut raw = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: `identifier` is a static NUL-terminated UTF-16 string, `raw` is writable
            // output storage, and mount construction runs at PASSIVE_LEVEL.
            BCryptOpenAlgorithmProvider(
                core::ptr::addr_of_mut!(raw),
                identifier.as_ptr(),
                core::ptr::null(),
                0,
            )
        };
        cng_status_to_driver(status)?;
        let handle = NonNull::new(raw).ok_or(DriverError::Core(Error::CryptographicFailure))?;
        Ok(Self(AlgorithmHandle(handle)))
    }

    /// Returns a non-owning handle copy bounded by mounted-runtime teardown.
    const fn borrowed(&self) -> AlgorithmHandle {
        self.0
    }
}

impl Drop for OwnedAlgorithmHandle {
    fn drop(&mut self) {
        let _status = unsafe {
            // SAFETY: This value owns the only close authority and mounted-runtime teardown drains
            // every operation object before algorithm providers are dropped.
            BCryptCloseAlgorithmProvider(self.0.as_raw(), 0)
        };
    }
}

impl core::fmt::Debug for OwnedAlgorithmHandle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OwnedAlgorithmHandle")
    }
}

/// Mount-owned symmetric algorithm plus its caller-supplied key-object requirement.
#[derive(Debug)]
struct SymmetricProvider {
    /// Algorithm close authority.
    algorithm: OwnedAlgorithmHandle,
    /// Exact minimum caller-owned key-object bytes.
    key_object_bytes: usize,
}

impl SymmetricProvider {
    /// Opens one caller-buffered key algorithm.
    /// # Errors
    ///
    /// Returns an error when the provider cannot be opened or its object length is invalid.
    fn open(identifier: &[u16]) -> DriverResult<Self> {
        let algorithm = OwnedAlgorithmHandle::open(identifier)?;
        let key_object_bytes = query_usize_property(algorithm.borrowed(), &OBJECT_LENGTH_PROPERTY)?;
        if key_object_bytes == 0 {
            return Err(DriverError::Core(Error::CryptographicFailure));
        }
        Ok(Self {
            algorithm,
            key_object_bytes,
        })
    }

    /// Opens one AES-family provider and verifies its fixed block geometry.
    /// # Errors
    ///
    /// Returns an error when provider construction fails or CNG reports a non-AES block length.
    fn open_aes(identifier: &[u16]) -> DriverResult<Self> {
        let provider = Self::open(identifier)?;
        let block_bytes =
            query_usize_property(provider.algorithm.borrowed(), &BLOCK_LENGTH_PROPERTY)?;
        if block_bytes != AES_BLOCK_BYTES {
            return Err(DriverError::Core(Error::CryptographicFailure));
        }
        Ok(provider)
    }

    /// Copies the execution values while retaining close authority in the mount.
    const fn execution(&self) -> SymmetricExecution {
        SymmetricExecution {
            algorithm: self.algorithm.borrowed(),
            key_object_bytes: self.key_object_bytes,
        }
    }
}

/// Non-owning symmetric execution profile copied into one operation.
#[derive(Clone, Copy)]
struct SymmetricExecution {
    /// Mount-owned CNG provider handle.
    algorithm: AlgorithmHandle,
    /// Active prefix of the operation-owned key-object buffer.
    key_object_bytes: usize,
}

/// Mount-owned hash algorithm and validated object geometry.
#[derive(Debug)]
struct HashProvider {
    /// Algorithm close authority.
    algorithm: OwnedAlgorithmHandle,
    /// Caller-owned reusable hash-object bytes.
    object_bytes: usize,
    /// Fixed digest bytes.
    digest_bytes: usize,
}

impl HashProvider {
    /// Opens and validates one fixed-output hash provider.
    /// # Errors
    ///
    /// Returns an error when the provider cannot be opened or reports inconsistent object or
    /// digest geometry.
    fn open(identifier: &[u16], expected_digest_bytes: usize) -> DriverResult<Self> {
        let algorithm = OwnedAlgorithmHandle::open(identifier)?;
        let object_bytes = query_usize_property(algorithm.borrowed(), &OBJECT_LENGTH_PROPERTY)?;
        let digest_bytes = query_usize_property(algorithm.borrowed(), &HASH_LENGTH_PROPERTY)?;
        if object_bytes == 0 || digest_bytes != expected_digest_bytes {
            return Err(DriverError::Core(Error::CryptographicFailure));
        }
        Ok(Self {
            algorithm,
            object_bytes,
            digest_bytes,
        })
    }
}

/// Mount-scoped immutable CNG providers.
///
/// Algorithm handles are opened once while mounting at PASSIVE_LEVEL. Mutable hash/key objects and
/// their backing buffers never live here; each admitted operation owns those separately.
#[derive(Debug)]
pub(crate) struct CngProvider {
    /// AES-256-XTS contents provider.
    xts: SymmetricProvider,
    /// AES-256 ECB primitive used to implement Linux-compatible CBC-CS3.
    aes_ecb: SymmetricProvider,
    /// HKDF-SHA512 key derivation provider.
    hkdf: SymmetricProvider,
    /// SHA-256 provider.
    sha256: HashProvider,
    /// SHA-512 provider.
    sha512: HashProvider,
}

impl CngProvider {
    /// Opens every production cryptographic primitive and validates its immutable geometry.
    /// # Errors
    ///
    /// Returns an error when a provider is unavailable, reports unexpected geometry, or CNG runs
    /// out of resources during mount construction.
    pub(crate) fn try_open() -> DriverResult<Self> {
        let xts = SymmetricProvider::open_aes(&XTS_AES_ALGORITHM)?;
        let aes_ecb = SymmetricProvider::open_aes(&AES_ALGORITHM)?;
        set_wide_property(
            aes_ecb.algorithm.borrowed(),
            &CHAINING_MODE_PROPERTY,
            &CHAINING_MODE_ECB,
        )?;
        let hkdf = SymmetricProvider::open(&HKDF_ALGORITHM)?;
        let sha256 = HashProvider::open(&SHA256_ALGORITHM, 32)?;
        let sha512 = HashProvider::open(&SHA512_ALGORITHM, 64)?;
        Ok(Self {
            xts,
            aes_ecb,
            hkdf,
            sha256,
            sha512,
        })
    }

    /// Allocates every mutable object and nonpaged work buffer needed by one operation.
    /// # Errors
    ///
    /// Returns an error when nonpaged allocation or reusable-hash construction fails.
    pub(crate) fn try_new_operation(&self) -> DriverResult<CngOperation> {
        let key_object_bytes = self
            .xts
            .key_object_bytes
            .max(self.aes_ecb.key_object_bytes)
            .max(self.hkdf.key_object_bytes);
        let key_object = DriverVec::try_repeated_copy(0_u8, key_object_bytes)?;
        let sha256 = ReusableHash::try_new(&self.sha256)?;
        let sha512 = ReusableHash::try_new(&self.sha512)?;
        Ok(CngOperation {
            xts: self.xts.execution(),
            aes_ecb: self.aes_ecb.execution(),
            hkdf: self.hkdf.execution(),
            sha256,
            sha512,
            key_object,
        })
    }
}

/// Operation-owned reusable hash object and address-stable nonpaged backing allocation.
struct ReusableHash {
    /// CNG hash identity borrowing the mount-owned algorithm provider.
    handle: NonNull<c_void>,
    /// Hash object bytes retained at one allocation address until `BCryptDestroyHash`.
    object: DriverVec<u8>,
    /// Fixed digest length validated at mount time.
    digest_bytes: usize,
}

impl ReusableHash {
    /// Allocates and constructs one reusable unkeyed hash object.
    /// # Errors
    ///
    /// Returns an error when the stable object allocation, ABI conversion, CNG construction, or
    /// returned handle validation fails.
    fn try_new(provider: &HashProvider) -> DriverResult<Self> {
        let mut object = DriverVec::try_repeated_copy(0_u8, provider.object_bytes)?;
        let object_bytes =
            u32::try_from(object.len()).map_err(|_| DriverError::InvalidBufferSize)?;
        let mut raw = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: The object allocation is writable and remains address-stable in the returned
            // value until the hash handle is destroyed. This is an unkeyed reusable hash.
            BCryptCreateHash(
                provider.algorithm.borrowed().as_raw(),
                core::ptr::addr_of_mut!(raw),
                object.as_mut_slice().as_mut_ptr(),
                object_bytes,
                core::ptr::null_mut(),
                0,
                BCRYPT_HASH_REUSABLE_FLAG,
            )
        };
        cng_status_to_driver(status)?;
        let handle = NonNull::new(raw).ok_or(DriverError::Core(Error::CryptographicFailure))?;
        Ok(Self {
            handle,
            object,
            digest_bytes: provider.digest_bytes,
        })
    }

    /// Hashes one input and lets CNG reset this reusable object after finalization.
    /// # Errors
    ///
    /// Returns an error when the requested digest size differs from the mounted provider, an ABI
    /// length overflows, or CNG hashing/finalization fails.
    fn digest<const N: usize>(&mut self, input: &[u8]) -> Ext4Result<[u8; N]> {
        if self.digest_bytes != N {
            return Err(Error::CryptographicFailure);
        }
        let input_bytes = u32::try_from(input.len()).map_err(|_| Error::ArithmeticOverflow)?;
        let status = unsafe {
            // SAFETY: `input` remains readable for exactly `input_bytes`; the reusable hash handle
            // and its object allocation are exclusively owned by this operation.
            BCryptHashData(
                self.handle.as_ptr(),
                input.as_ptr().cast_mut(),
                input_bytes,
                0,
            )
        };
        cng_status_to_core(status)?;
        let mut output = [0_u8; N];
        let output_bytes = u32::try_from(N).map_err(|_| Error::ArithmeticOverflow)?;
        let status = unsafe {
            // SAFETY: `output` is writable for its fixed length. Successful finalization resets a
            // hash created with BCRYPT_HASH_REUSABLE_FLAG.
            BCryptFinishHash(self.handle.as_ptr(), output.as_mut_ptr(), output_bytes, 0)
        };
        cng_status_to_core(status)?;
        Ok(output)
    }
}

impl Drop for ReusableHash {
    fn drop(&mut self) {
        let _status = unsafe {
            // SAFETY: This operation owns the sole destroy authority and the backing allocation is
            // still live for the duration of this call.
            BCryptDestroyHash(self.handle.as_ptr())
        };
        self.object.as_mut_slice().fill(0);
    }
}

impl core::fmt::Debug for ReusableHash {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReusableHash")
            .field("object_bytes", &self.object.len())
            .field("digest_bytes", &self.digest_bytes)
            .finish()
    }
}

// SAFETY: The object and handle move together, their heap allocation is address-stable, and every
// call/destroy executes on the sole PASSIVE_LEVEL reactor thread.
unsafe impl Send for ReusableHash {}

/// Generated symmetric key whose borrow prevents reuse of its caller-owned object buffer.
struct GeneratedKey<'object> {
    /// CNG key identity.
    handle: NonNull<c_void>,
    /// Mutable object-buffer lease retained through `BCryptDestroyKey`.
    object: &'object mut [u8],
}

impl GeneratedKey<'_> {
    /// Returns the opaque CNG key identity.
    const fn as_raw(&self) -> *mut c_void {
        self.handle.as_ptr()
    }
}

impl Drop for GeneratedKey<'_> {
    fn drop(&mut self) {
        let _status = unsafe {
            // SAFETY: This value owns the sole destroy authority; its borrowed key-object buffer
            // remains writable and live until this destructor finishes.
            BCryptDestroyKey(self.handle.as_ptr())
        };
        self.object.fill(0);
    }
}

/// All mutable CNG state owned by one top-level operation.
///
/// This value is built fallibly before the operation can issue lower writes. It moves by value with
/// the suspended operation and is never referenced from a completion context.
#[derive(Debug)]
pub(crate) struct CngOperation {
    /// Mount-owned XTS provider execution values.
    xts: SymmetricExecution,
    /// Mount-owned AES-ECB provider execution values.
    aes_ecb: SymmetricExecution,
    /// Mount-owned HKDF provider execution values.
    hkdf: SymmetricExecution,
    /// Reusable SHA-256 object.
    sha256: ReusableHash,
    /// Reusable SHA-512 object.
    sha512: ReusableHash,
    /// Single nonpaged buffer leased exclusively to each generated key.
    key_object: DriverVec<u8>,
}

impl core::fmt::Debug for SymmetricExecution {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SymmetricExecution")
            .field("key_object_bytes", &self.key_object_bytes)
            .finish()
    }
}

// SAFETY: Operation admission and every cryptographic call/drop execute on the sole PASSIVE_LEVEL
// reactor. Opaque provider handles remain live until that reactor drains every operation.
unsafe impl Send for CngOperation {}

impl CryptographicOperation for CngOperation {
    fn fill_random(&mut self, output: &mut [u8]) -> Ext4Result<()> {
        let output_bytes = u32::try_from(output.len()).map_err(|_| Error::ArithmeticOverflow)?;
        let status = unsafe {
            // SAFETY: A null algorithm handle selects the system-preferred RNG under this flag;
            // `output` is exclusively writable for exactly `output_bytes`.
            BCryptGenRandom(
                core::ptr::null_mut(),
                output.as_mut_ptr(),
                output_bytes,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        cng_status_to_core(status)
    }

    fn hkdf_sha512(&mut self, key: &[u8], info: &[u8], output: &mut [u8]) -> Ext4Result<()> {
        let generated = generate_key(self.hkdf, self.key_object.as_mut_slice(), key)?;
        set_wide_property_core(
            generated.as_raw(),
            &HKDF_HASH_ALGORITHM_PROPERTY,
            &SHA512_ALGORITHM,
        )?;
        let status = unsafe {
            // SAFETY: A null, zero-length salt is explicitly supported by the HKDF provider and
            // finalizes extract state after the hash property has been selected.
            BCryptSetProperty(
                generated.as_raw(),
                HKDF_SALT_AND_FINALIZE_PROPERTY.as_ptr(),
                core::ptr::null_mut(),
                0,
                0,
            )
        };
        cng_status_to_core(status)?;

        let info_bytes = u32::try_from(info.len()).map_err(|_| Error::ArithmeticOverflow)?;
        let output_bytes = u32::try_from(output.len()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut parameter = BCryptBuffer {
            buffer_bytes: info_bytes,
            buffer_type: KDF_HKDF_INFO,
            buffer: info.as_ptr().cast_mut().cast(),
        };
        let mut parameters = BCryptBufferDesc {
            version: BCRYPT_BUFFER_VERSION,
            buffer_count: 1,
            buffers: core::ptr::addr_of_mut!(parameter),
        };
        let mut result_bytes = 0_u32;
        let status = unsafe {
            // SAFETY: The descriptor and info bytes remain live for the synchronous derivation;
            // `output` is writable for its exact length and the generated key retains its object
            // buffer lease throughout the call.
            BCryptKeyDerivation(
                generated.as_raw(),
                core::ptr::addr_of_mut!(parameters),
                output.as_mut_ptr(),
                output_bytes,
                core::ptr::addr_of_mut!(result_bytes),
                0,
            )
        };
        cng_status_to_core(status)?;
        if result_bytes != output_bytes {
            return Err(Error::CryptographicFailure);
        }
        Ok(())
    }

    fn encrypt_aes_256_xts(
        &mut self,
        key: &[u8; 64],
        data_unit: u64,
        buffer: &mut [u8],
    ) -> Ext4Result<()> {
        crypt_xts(
            self.xts,
            self.key_object.as_mut_slice(),
            key,
            data_unit,
            buffer,
            CipherDirection::Encrypt,
        )
    }

    fn decrypt_aes_256_xts(
        &mut self,
        key: &[u8; 64],
        data_unit: u64,
        buffer: &mut [u8],
    ) -> Ext4Result<()> {
        crypt_xts(
            self.xts,
            self.key_object.as_mut_slice(),
            key,
            data_unit,
            buffer,
            CipherDirection::Decrypt,
        )
    }

    fn encrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], buffer: &mut [u8]) -> Ext4Result<()> {
        let generated = generate_key(self.aes_ecb, self.key_object.as_mut_slice(), key)?;
        encrypt_cbc_cs3(&generated, buffer)
    }

    fn decrypt_aes_256_cbc_cs3(&mut self, key: &[u8; 32], buffer: &mut [u8]) -> Ext4Result<()> {
        let generated = generate_key(self.aes_ecb, self.key_object.as_mut_slice(), key)?;
        decrypt_cbc_cs3(&generated, buffer)
    }

    fn sha256(&mut self, input: &[u8]) -> Ext4Result<[u8; 32]> {
        self.sha256.digest(input)
    }

    fn sha512(&mut self, input: &[u8]) -> Ext4Result<[u8; 64]> {
        self.sha512.digest(input)
    }
}

/// Symmetric primitive direction selected by the typed trait method.
#[derive(Clone, Copy)]
enum CipherDirection {
    /// Encrypt in place.
    Encrypt,
    /// Decrypt in place.
    Decrypt,
}

/// Generates one key into a checked prefix of the operation-owned object buffer.
/// # Errors
///
/// Returns an error when the object prefix or ABI lengths are invalid, or CNG cannot construct a
/// non-null key handle.
fn generate_key<'object>(
    execution: SymmetricExecution,
    key_object: &'object mut [u8],
    secret: &[u8],
) -> Ext4Result<GeneratedKey<'object>> {
    let object = key_object
        .get_mut(..execution.key_object_bytes)
        .ok_or(Error::CryptographicFailure)?;
    object.fill(0);
    let object_bytes = u32::try_from(object.len()).map_err(|_| Error::ArithmeticOverflow)?;
    let secret_bytes = u32::try_from(secret.len()).map_err(|_| Error::ArithmeticOverflow)?;
    let mut raw = core::ptr::null_mut();
    let status = unsafe {
        // SAFETY: `object` is an exclusively borrowed, address-stable nonpaged allocation prefix;
        // `secret` remains readable during this synchronous call. The returned key cannot outlive
        // the object borrow.
        BCryptGenerateSymmetricKey(
            execution.algorithm.as_raw(),
            core::ptr::addr_of_mut!(raw),
            object.as_mut_ptr(),
            object_bytes,
            secret.as_ptr().cast_mut(),
            secret_bytes,
            0,
        )
    };
    if let Err(error) = cng_status_to_core(status) {
        object.fill(0);
        return Err(error);
    }
    let Some(handle) = NonNull::new(raw) else {
        object.fill(0);
        return Err(Error::CryptographicFailure);
    };
    Ok(GeneratedKey { handle, object })
}

/// Applies AES-256-XTS in place with the Linux little-endian data-unit tweak.
/// # Errors
///
/// Returns an error for an invalid data-unit length, key construction/property failure, or CNG
/// encryption/decryption failure.
fn crypt_xts(
    execution: SymmetricExecution,
    key_object: &mut [u8],
    key: &[u8; 64],
    data_unit: u64,
    buffer: &mut [u8],
    direction: CipherDirection,
) -> Ext4Result<()> {
    if buffer.len() < AES_BLOCK_BYTES || !buffer.len().is_multiple_of(AES_BLOCK_BYTES) {
        return Err(Error::InvalidWriteRange);
    }
    let generated = generate_key(execution, key_object, key)?;
    let data_unit_bytes = u32::try_from(buffer.len()).map_err(|_| Error::ArithmeticOverflow)?;
    set_u32_property_core(
        generated.as_raw(),
        &MESSAGE_BLOCK_LENGTH_PROPERTY,
        data_unit_bytes,
    )?;
    let mut tweak = data_unit.to_le_bytes();
    crypt_in_place(&generated, buffer, Some(&mut tweak), direction)
}

/// Applies one CNG symmetric key to the same caller-owned input/output range.
/// # Errors
///
/// Returns an error when a length is not representable, CNG rejects the operation, or the provider
/// reports a short result.
fn crypt_in_place(
    key: &GeneratedKey<'_>,
    buffer: &mut [u8],
    initialization_vector: Option<&mut [u8]>,
    direction: CipherDirection,
) -> Ext4Result<()> {
    let buffer_bytes = u32::try_from(buffer.len()).map_err(|_| Error::ArithmeticOverflow)?;
    let (iv_pointer, iv_bytes) = match initialization_vector {
        Some(iv) => (
            iv.as_mut_ptr(),
            u32::try_from(iv.len()).map_err(|_| Error::ArithmeticOverflow)?,
        ),
        None => (core::ptr::null_mut(), 0),
    };
    let mut result_bytes = 0_u32;
    let status = match direction {
        CipherDirection::Encrypt => unsafe {
            // SAFETY: CNG permits in-place encryption. `buffer` and the optional IV are
            // exclusively writable, and `key` retains the backing object for the entire call.
            BCryptEncrypt(
                key.as_raw(),
                buffer.as_mut_ptr(),
                buffer_bytes,
                core::ptr::null_mut(),
                iv_pointer,
                iv_bytes,
                buffer.as_mut_ptr(),
                buffer_bytes,
                core::ptr::addr_of_mut!(result_bytes),
                0,
            )
        },
        CipherDirection::Decrypt => unsafe {
            // SAFETY: CNG permits in-place decryption. `buffer` and the optional IV are
            // exclusively writable, and `key` retains the backing object for the entire call.
            BCryptDecrypt(
                key.as_raw(),
                buffer.as_mut_ptr(),
                buffer_bytes,
                core::ptr::null_mut(),
                iv_pointer,
                iv_bytes,
                buffer.as_mut_ptr(),
                buffer_bytes,
                core::ptr::addr_of_mut!(result_bytes),
                0,
            )
        },
    };
    cng_status_to_core(status)?;
    if result_bytes != buffer_bytes {
        return Err(Error::CryptographicFailure);
    }
    Ok(())
}

/// Encrypts one exact AES block with the operation's ECB key.
/// # Errors
///
/// Returns an error when CNG cannot encrypt the block exactly in place.
fn encrypt_block(key: &GeneratedKey<'_>, block: &mut [u8; AES_BLOCK_BYTES]) -> Ext4Result<()> {
    crypt_in_place(key, block, None, CipherDirection::Encrypt)
}

/// Decrypts one exact AES block with the operation's ECB key.
/// # Errors
///
/// Returns an error when CNG cannot decrypt the block exactly in place.
fn decrypt_block(key: &GeneratedKey<'_>, block: &mut [u8; AES_BLOCK_BYTES]) -> Ext4Result<()> {
    crypt_in_place(key, block, None, CipherDirection::Decrypt)
}

/// Linux `cts(cbc(aes))` encryption, equivalent to CBC-CS3 with a zero IV.
/// # Errors
///
/// Returns an error when the input is too short, checked partition arithmetic fails, or an AES
/// block cannot be transformed.
fn encrypt_cbc_cs3(key: &GeneratedKey<'_>, buffer: &mut [u8]) -> Ext4Result<()> {
    if buffer.len() < AES_BLOCK_BYTES {
        return Err(Error::InvalidName);
    }
    let remainder = buffer.len() % AES_BLOCK_BYTES;
    let full_bytes = buffer.len().saturating_sub(remainder);
    let mut previous = [0_u8; AES_BLOCK_BYTES];
    let (full, tail) = buffer
        .split_at_mut_checked(full_bytes)
        .ok_or(Error::CryptographicFailure)?;
    let (blocks, unexpected_tail) = full.as_chunks_mut::<AES_BLOCK_BYTES>();
    if !unexpected_tail.is_empty() {
        return Err(Error::CryptographicFailure);
    }
    for chunk in blocks {
        let mut block = [0_u8; AES_BLOCK_BYTES];
        copy_equal(&mut block, chunk)?;
        xor_block(&mut block, &previous);
        encrypt_block(key, &mut block)?;
        copy_equal(chunk, &block)?;
        previous = block;
    }

    if remainder == 0 {
        if full_bytes > AES_BLOCK_BYTES {
            let pair_start = full_bytes
                .checked_sub(AES_BLOCK_BYTES * 2)
                .ok_or(Error::ArithmeticOverflow)?;
            let pair = full
                .get_mut(pair_start..full_bytes)
                .ok_or(Error::CryptographicFailure)?;
            let (penultimate, last) = pair
                .split_at_mut_checked(AES_BLOCK_BYTES)
                .ok_or(Error::CryptographicFailure)?;
            for (left, right) in penultimate.iter_mut().zip(last.iter_mut()) {
                core::mem::swap(left, right);
            }
        }
        return Ok(());
    }

    let mut final_block = [0_u8; AES_BLOCK_BYTES];
    for (destination, source) in final_block.iter_mut().zip(tail.iter().copied()) {
        *destination = source;
    }
    xor_block(&mut final_block, &previous);
    encrypt_block(key, &mut final_block)?;
    let penultimate_start = full_bytes
        .checked_sub(AES_BLOCK_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    copy_equal(
        full.get_mut(penultimate_start..full_bytes)
            .ok_or(Error::CryptographicFailure)?,
        &final_block,
    )?;
    copy_equal(
        tail,
        previous
            .get(..remainder)
            .ok_or(Error::CryptographicFailure)?,
    )
}

/// Linux `cts(cbc(aes))` decryption, equivalent to CBC-CS3 with a zero IV.
/// # Errors
///
/// Returns an error when the input is too short, checked partition arithmetic fails, or an AES
/// block cannot be transformed.
fn decrypt_cbc_cs3(key: &GeneratedKey<'_>, buffer: &mut [u8]) -> Ext4Result<()> {
    if buffer.len() < AES_BLOCK_BYTES {
        return Err(Error::InvalidName);
    }
    if buffer.len() == AES_BLOCK_BYTES {
        let mut block = [0_u8; AES_BLOCK_BYTES];
        copy_equal(&mut block, buffer)?;
        decrypt_block(key, &mut block)?;
        return copy_equal(buffer, &block);
    }

    let block_count = buffer
        .len()
        .checked_add(AES_BLOCK_BYTES - 1)
        .ok_or(Error::ArithmeticOverflow)?
        / AES_BLOCK_BYTES;
    let main_blocks = block_count.saturating_sub(2);
    let main_bytes = main_blocks
        .checked_mul(AES_BLOCK_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    let mut previous = [0_u8; AES_BLOCK_BYTES];
    let main = buffer
        .get_mut(..main_bytes)
        .ok_or(Error::CryptographicFailure)?;
    let (blocks, unexpected_tail) = main.as_chunks_mut::<AES_BLOCK_BYTES>();
    if !unexpected_tail.is_empty() {
        return Err(Error::CryptographicFailure);
    }
    for chunk in blocks {
        let mut ciphertext = [0_u8; AES_BLOCK_BYTES];
        copy_equal(&mut ciphertext, chunk)?;
        let mut plaintext = ciphertext;
        decrypt_block(key, &mut plaintext)?;
        xor_block(&mut plaintext, &previous);
        copy_equal(chunk, &plaintext)?;
        previous = ciphertext;
    }

    let tail = buffer
        .get_mut(main_bytes..)
        .ok_or(Error::CryptographicFailure)?;
    let stolen_bytes = tail
        .len()
        .checked_sub(AES_BLOCK_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    if stolen_bytes == 0 || stolen_bytes > AES_BLOCK_BYTES {
        return Err(Error::CryptographicFailure);
    }
    let (last_full, stolen) = tail
        .split_at_mut_checked(AES_BLOCK_BYTES)
        .ok_or(Error::CryptographicFailure)?;
    let mut decrypted_last = [0_u8; AES_BLOCK_BYTES];
    copy_equal(&mut decrypted_last, last_full)?;
    decrypt_block(key, &mut decrypted_last)?;

    let mut reconstructed = [0_u8; AES_BLOCK_BYTES];
    copy_equal(
        reconstructed
            .get_mut(..stolen_bytes)
            .ok_or(Error::CryptographicFailure)?,
        stolen,
    )?;
    copy_equal(
        reconstructed
            .get_mut(stolen_bytes..)
            .ok_or(Error::CryptographicFailure)?,
        decrypted_last
            .get(stolen_bytes..)
            .ok_or(Error::CryptographicFailure)?,
    )?;

    for (plaintext, ciphertext) in decrypted_last.iter_mut().zip(reconstructed) {
        *plaintext ^= ciphertext;
    }
    decrypt_block(key, &mut reconstructed)?;
    xor_block(&mut reconstructed, &previous);
    copy_equal(last_full, &reconstructed)?;
    copy_equal(
        stolen,
        decrypted_last
            .get(..stolen_bytes)
            .ok_or(Error::CryptographicFailure)?,
    )
}

/// XORs two exact AES blocks without indexing.
fn xor_block(destination: &mut [u8; AES_BLOCK_BYTES], source: &[u8; AES_BLOCK_BYTES]) {
    for (left, right) in destination.iter_mut().zip(source) {
        *left ^= *right;
    }
}

/// Copies only equal-length ranges and returns an error instead of invoking slice-copy panics.
/// # Errors
///
/// Returns [`Error::CryptographicFailure`] when the ranges have different lengths.
fn copy_equal(destination: &mut [u8], source: &[u8]) -> Ext4Result<()> {
    if destination.len() != source.len() {
        return Err(Error::CryptographicFailure);
    }
    for (output, input) in destination.iter_mut().zip(source) {
        *output = *input;
    }
    Ok(())
}

/// Queries one `ULONG` CNG property and converts it to the host collection length domain.
/// # Errors
///
/// Returns an error when ABI conversion or CNG lookup fails, or the provider returns a value with
/// an unexpected byte length.
fn query_usize_property(algorithm: AlgorithmHandle, property: &[u16]) -> DriverResult<usize> {
    let mut value = 0_u32;
    let mut result_bytes = 0_u32;
    let output_bytes =
        u32::try_from(core::mem::size_of::<u32>()).map_err(|_| DriverError::InvalidBufferSize)?;
    let status = unsafe {
        // SAFETY: `property` is NUL-terminated, `value` is aligned writable ULONG storage, and
        // `result_bytes` receives the provider's exact output length.
        BCryptGetProperty(
            algorithm.as_raw(),
            property.as_ptr(),
            core::ptr::addr_of_mut!(value).cast(),
            output_bytes,
            core::ptr::addr_of_mut!(result_bytes),
            0,
        )
    };
    cng_status_to_driver(status)?;
    if result_bytes != output_bytes {
        return Err(DriverError::Core(Error::CryptographicFailure));
    }
    usize::try_from(value).map_err(|_| DriverError::InvalidBufferSize)
}

/// Sets one NUL-terminated UTF-16 algorithm property during mount construction.
/// # Errors
///
/// Returns an error when the property byte length is not representable or CNG rejects the value.
fn set_wide_property(
    algorithm: AlgorithmHandle,
    property: &[u16],
    value: &[u16],
) -> DriverResult<()> {
    let value_bytes = value
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidBufferSize)
        .and_then(|bytes| u32::try_from(bytes).map_err(|_| DriverError::InvalidBufferSize))?;
    let status = unsafe {
        // SAFETY: Both strings are NUL-terminated static UTF-16; CNG reads the value synchronously.
        BCryptSetProperty(
            algorithm.as_raw(),
            property.as_ptr(),
            value.as_ptr().cast_mut().cast(),
            value_bytes,
            0,
        )
    };
    cng_status_to_driver(status)
}

/// Sets one NUL-terminated UTF-16 key property in the ext4-core failure domain.
/// # Errors
///
/// Returns an error when the property byte length is not representable or CNG rejects the value.
fn set_wide_property_core(object: *mut c_void, property: &[u16], value: &[u16]) -> Ext4Result<()> {
    let value_bytes = value
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(Error::ArithmeticOverflow)
        .and_then(|bytes| u32::try_from(bytes).map_err(|_| Error::ArithmeticOverflow))?;
    let status = unsafe {
        // SAFETY: Both strings are NUL-terminated static UTF-16; the generated key and its object
        // buffer remain live while CNG consumes the property synchronously.
        BCryptSetProperty(
            object,
            property.as_ptr(),
            value.as_ptr().cast_mut().cast(),
            value_bytes,
            0,
        )
    };
    cng_status_to_core(status)
}

/// Sets one `ULONG` key property in the ext4-core failure domain.
/// # Errors
///
/// Returns an error when the ABI length is not representable or CNG rejects the value.
fn set_u32_property_core(object: *mut c_void, property: &[u16], mut value: u32) -> Ext4Result<()> {
    let value_bytes =
        u32::try_from(core::mem::size_of::<u32>()).map_err(|_| Error::ArithmeticOverflow)?;
    let status = unsafe {
        // SAFETY: `property` is NUL-terminated and `value` is live aligned ULONG storage consumed
        // synchronously while the generated key remains valid.
        BCryptSetProperty(
            object,
            property.as_ptr(),
            core::ptr::addr_of_mut!(value).cast(),
            value_bytes,
            0,
        )
    };
    cng_status_to_core(status)
}

/// Converts CNG NTSTATUS into a fallible mount-construction result.
/// # Errors
///
/// Returns a resource or cryptographic driver error for any unsuccessful CNG status.
fn cng_status_to_driver(status: NTSTATUS) -> DriverResult<()> {
    if NT_SUCCESS(status) {
        Ok(())
    } else if status == STATUS_NO_MEMORY || status == STATUS_INSUFFICIENT_RESOURCES {
        Err(DriverError::InsufficientResources)
    } else {
        Err(DriverError::Core(Error::CryptographicFailure))
    }
}

/// Converts CNG NTSTATUS into the ext4 cryptographic failure domain.
/// # Errors
///
/// Returns [`Error::CryptographicFailure`] for any unsuccessful CNG status.
fn cng_status_to_core(status: NTSTATUS) -> Ext4Result<()> {
    if NT_SUCCESS(status) {
        Ok(())
    } else {
        Err(Error::CryptographicFailure)
    }
}

#[cfg(test)]
mod tests {
    use ext4_core::{CryptographicOperation, Error};
    use wdk_sys::{STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

    use super::{CngProvider, cng_status_to_core, decrypt_cbc_cs3, encrypt_cbc_cs3, generate_key};

    macro_rules! must {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => {
                    let unexpected_error: Option<()> = None;
                    assert!(
                        unexpected_error.is_some(),
                        "unexpected CNG test error: {error:?}"
                    );
                    return;
                }
            }
        };
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn cng_status_mapping_preserves_success_and_crypto_failure() {
        assert_eq!(cng_status_to_core(STATUS_SUCCESS), Ok(()));
        assert_eq!(
            cng_status_to_core(STATUS_UNSUCCESSFUL),
            Err(Error::CryptographicFailure)
        );
    }

    /// # Panics
    ///
    /// Panics when CNG rejects standard SHA vectors or reusable-hash reset semantics.
    #[test]
    fn reusable_cng_hashes_match_standard_vectors() {
        let provider = must!(CngProvider::try_open());
        let mut operation = must!(provider.try_new_operation());
        let sha256 = must!(operation.sha256(b"abc"));
        let sha512 = must!(operation.sha512(b"abc"));
        assert_eq!(
            sha256,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(
            sha512,
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
            ]
        );
        assert_eq!(operation.sha256(b"abc"), Ok(sha256));
    }

    /// # Panics
    ///
    /// Panics when CNG HKDF-SHA512 diverges from Linux fscrypt v2 derivation vectors.
    #[test]
    fn cng_hkdf_sha512_matches_fscrypt_v2_vectors() {
        let provider = must!(CngProvider::try_open());
        let mut operation = must!(provider.try_new_operation());
        let mut master_key = [0_u8; 32];
        for (byte, value) in master_key.iter_mut().zip(0_u8..32) {
            *byte = value;
        }

        let mut identifier = [0_u8; 16];
        must!(operation.hkdf_sha512(&master_key, b"fscrypt\0\x01", &mut identifier));
        assert_eq!(
            identifier,
            [
                0x37, 0xd7, 0xd7, 0x6a, 0x59, 0x40, 0x00, 0x83, 0x28, 0x9c, 0x18, 0x55, 0x26, 0x73,
                0x0d, 0x34,
            ]
        );

        let info = b"fscrypt\0\x02\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf";
        let mut contents_key = [0_u8; 64];
        must!(operation.hkdf_sha512(&master_key, info, &mut contents_key));
        assert_eq!(
            contents_key,
            [
                0xe0, 0x80, 0x03, 0x95, 0x2a, 0x49, 0xa8, 0xfe, 0x90, 0x56, 0x87, 0x3d, 0x11, 0xe4,
                0xcb, 0x82, 0xe0, 0xa5, 0x21, 0x90, 0x20, 0x96, 0x0c, 0x35, 0x38, 0x71, 0x30, 0xa2,
                0xa1, 0x93, 0x82, 0x3e, 0xda, 0x7f, 0xd6, 0x41, 0xa7, 0xeb, 0x36, 0x5a, 0x44, 0xa3,
                0x90, 0xc1, 0x8e, 0x3c, 0x69, 0xf4, 0xa7, 0x73, 0x9a, 0xe4, 0x13, 0xdc, 0xc2, 0x0a,
                0x2d, 0x42, 0x66, 0xe2, 0xd2, 0x4c, 0x7f, 0x2a,
            ]
        );
        let mut filename_key = [0_u8; 32];
        must!(operation.hkdf_sha512(&master_key, info, &mut filename_key));
        assert_eq!(filename_key, contents_key[..32]);
    }

    /// # Panics
    ///
    /// Panics when CNG AES-256-XTS diverges from the IEEE 1619 vector used by Linux.
    #[test]
    fn cng_aes_256_xts_matches_linux_vector() {
        let provider = must!(CngProvider::try_open());
        let mut operation = must!(provider.try_new_operation());
        let key = [
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71,
            0x35, 0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59, 0x57, 0x49,
            0x66, 0x96, 0x76, 0x27, 0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84,
            0x62, 0x64, 0x33, 0x83, 0x27, 0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37,
            0x51, 0x05, 0x82, 0x09, 0x74, 0x94, 0x45, 0x92,
        ];
        let mut plaintext = [0_u8; 64];
        for (byte, value) in plaintext.iter_mut().zip(0_u8..64) {
            *byte = value;
        }
        let original = plaintext;

        must!(operation.encrypt_aes_256_xts(&key, 0xff, &mut plaintext));
        assert_eq!(
            plaintext,
            [
                0x1c, 0x3b, 0x3a, 0x10, 0x2f, 0x77, 0x03, 0x86, 0xe4, 0x83, 0x6c, 0x99, 0xe3, 0x70,
                0xcf, 0x9b, 0xea, 0x00, 0x80, 0x3f, 0x5e, 0x48, 0x23, 0x57, 0xa4, 0xae, 0x12, 0xd4,
                0x14, 0xa3, 0xe6, 0x3b, 0x5d, 0x31, 0xe2, 0x76, 0xf8, 0xfe, 0x4a, 0x8d, 0x66, 0xb3,
                0x17, 0xf9, 0xac, 0x68, 0x3f, 0x44, 0x68, 0x0a, 0x86, 0xac, 0x35, 0xad, 0xfc, 0x33,
                0x45, 0xbe, 0xfe, 0xcb, 0x4b, 0xb1, 0x88, 0xfd,
            ]
        );
        must!(operation.decrypt_aes_256_xts(&key, 0xff, &mut plaintext));
        assert_eq!(plaintext, original);
    }

    /// # Panics
    ///
    /// Panics when manual CBC-CS3 diverges from Linux's RFC 3962 vectors, including the exact
    /// one-block CBC rule and swapped exact-block tails.
    #[test]
    fn cng_cbc_cs3_matches_linux_rfc3962_vectors() {
        let provider = must!(CngProvider::try_open());
        let mut operation = must!(provider.try_new_operation());
        let key = *b"chicken teriyaki";
        let generated = must!(generate_key(
            operation.aes_ecb,
            operation.key_object.as_mut_slice(),
            &key
        ));
        let plaintext = b"I would like the General Gau's Chicken, please, and wonton soup.";
        let vectors: &[(&[u8], &[u8])] = &[
            (
                b"I would like the",
                b"\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
            ),
            (
                b"I would like the ",
                b"\xc6\x35\x35\x68\xf2\xbf\x8c\xb4\xd8\xa5\x80\x36\x2d\xa7\xff\x7f\x97",
            ),
            (
                b"I would like the General Gau's ",
                b"\xfc\x00\x78\x3e\x0e\xfd\xb2\xc1\xd4\x45\xd4\xc8\xef\xf7\xed\x22\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5",
            ),
            (
                b"I would like the General Gau's C",
                b"\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84",
            ),
            (
                b"I would like the General Gau's Chicken, please,",
                b"\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84\xb3\xff\xfd\x94\x0c\x16\xa1\x8c\x1b\x55\x49\xd2\xf8\x38\x02\x9e\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5",
            ),
            (
                b"I would like the General Gau's Chicken, please, ",
                b"\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8",
            ),
            (
                plaintext,
                b"\x97\x68\x72\x68\xd6\xec\xcc\xc0\xc0\x7b\x25\xe2\x5e\xcf\xe5\x84\x39\x31\x25\x23\xa7\x86\x62\xd5\xbe\x7f\xcb\xcc\x98\xeb\xf5\xa8\x48\x07\xef\xe8\x36\xee\x89\xa5\x26\x73\x0d\xbc\x2f\x7b\xc8\x40\x9d\xad\x8b\xbb\x96\xc4\xcd\xc0\x3b\xc1\x03\xe1\xa1\x94\xbb\xd8",
            ),
        ];

        for (cleartext, expected) in vectors {
            let mut ciphertext = cleartext.to_vec();
            must!(encrypt_cbc_cs3(&generated, &mut ciphertext));
            assert_eq!(&ciphertext, expected);
            must!(decrypt_cbc_cs3(&generated, &mut ciphertext));
            assert_eq!(&ciphertext, cleartext);
        }
    }
}

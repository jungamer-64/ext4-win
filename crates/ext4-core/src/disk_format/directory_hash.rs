//! Root-selected ext4 directory-name hashing for HTree routing.

use core::array;

use crate::disk_format::superblock::{DirectoryHashSeed, DirectoryHashVersion};
use crate::platform::name::Ext4Name;

/// Seed prescribed by the ext4 format when every stored seed word is zero.
const FORMAT_DEFAULT_SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
/// Primary value reserved by the HTree format for the end marker.
const END_MARKER_HASH: u32 = 0xffff_fffe;
/// Greatest primary value available to an ordinary directory name.
const LAST_NAME_HASH: u32 = 0xffff_fffc;
/// Number of bytes consumed by one half-MD4 compression step.
const HALF_MD4_INPUT_BYTES: usize = 32;
/// Number of bytes consumed by one TEA compression step.
const TEA_INPUT_BYTES: usize = 16;
/// Additive increment applied by each TEA round.
const TEA_ROUND_INCREMENT: u32 = 0x9e37_79b9;
/// Update order shared by each eight-step half-MD4 round.
const LANE_UPDATE_ORDER: [Lane; 8] = [
    Lane::A,
    Lane::D,
    Lane::C,
    Lane::B,
    Lane::A,
    Lane::D,
    Lane::C,
    Lane::B,
];

/// Hash pair consumed by HTree routing and collision ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DirectoryHash {
    /// Primary HTree routing value.
    pub(crate) major: u32,
    /// Secondary value used to order primary-hash collisions.
    pub(crate) minor: u32,
}

impl DirectoryHash {
    /// Converts an algorithm result into the HTree name-key domain.
    const fn from_algorithm(major: u32, minor: u32) -> Self {
        let major = major & !1;
        let major = if major == END_MARKER_HASH {
            LAST_NAME_HASH
        } else {
            major
        };
        Self { major, minor }
    }
}

/// Immutable hash scheme selected by validated superblock and HTree-root metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryHashScheme {
    /// Effective seed after applying the format-defined zero-seed rule.
    seed: HashState,
    /// Algorithm and byte interpretation selected by the root version.
    version: DirectoryHashVersion,
}

impl DirectoryHashScheme {
    /// Builds the scheme selected by validated on-disk metadata.
    #[must_use]
    pub(crate) fn from_metadata(seed: DirectoryHashSeed, version: DirectoryHashVersion) -> Self {
        let words = seed.words();
        let effective = if words.iter().any(|word| *word != 0) {
            words
        } else {
            FORMAT_DEFAULT_SEED
        };
        Self {
            seed: HashState::from_words(effective),
            version,
        }
    }

    /// Produces the normalized HTree key for one validated ext4 name.
    #[must_use]
    pub(crate) fn hash(self, name: &Ext4Name) -> DirectoryHash {
        let (major, minor) = match self.version {
            DirectoryHashVersion::Legacy => rolling_hash(name.bytes(), NameByteEncoding::Signed),
            DirectoryHashVersion::LegacyUnsigned => {
                rolling_hash(name.bytes(), NameByteEncoding::Unsigned)
            }
            DirectoryHashVersion::HalfMd4 => {
                self.hash_with_half_md4(name.bytes(), NameByteEncoding::Signed)
            }
            DirectoryHashVersion::HalfMd4Unsigned => {
                self.hash_with_half_md4(name.bytes(), NameByteEncoding::Unsigned)
            }
            DirectoryHashVersion::Tea => self.hash_with_tea(name.bytes(), NameByteEncoding::Signed),
            DirectoryHashVersion::TeaUnsigned => {
                self.hash_with_tea(name.bytes(), NameByteEncoding::Unsigned)
            }
        };
        DirectoryHash::from_algorithm(major, minor)
    }

    /// Compresses the full name in 32-byte half-MD4 input blocks.
    fn hash_with_half_md4(self, bytes: &[u8], encoding: NameByteEncoding) -> (u32, u32) {
        let mut state = self.seed;
        let mut start = 0_usize;
        while start < bytes.len() {
            let block = NameWordBlock::<8>::at(bytes, start, encoding);
            state.compress_half_md4(block);
            start = start.saturating_add(HALF_MD4_INPUT_BYTES);
        }
        (state.b, state.c)
    }

    /// Compresses the full name in 16-byte TEA input blocks.
    fn hash_with_tea(self, bytes: &[u8], encoding: NameByteEncoding) -> (u32, u32) {
        let mut state = self.seed;
        let mut start = 0_usize;
        while start < bytes.len() {
            let block = NameWordBlock::<4>::at(bytes, start, encoding);
            state.compress_tea(block);
            start = start.saturating_add(TEA_INPUT_BYTES);
        }
        (state.a, state.b)
    }
}

/// Signedness assigned to name bytes by an on-disk hash version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NameByteEncoding {
    /// Sign-extend each byte before incorporating it.
    Signed,
    /// Zero-extend each byte before incorporating it.
    Unsigned,
}

impl NameByteEncoding {
    /// Converts one raw name byte into the algorithm's 32-bit arithmetic domain.
    fn value(self, byte: u8) -> u32 {
        match self {
            Self::Signed => {
                let signed = i8::from_ne_bytes([byte]);
                u32::from_ne_bytes(i32::from(signed).to_ne_bytes())
            }
            Self::Unsigned => u32::from(byte),
        }
    }
}

/// Fixed-width words derived from the remaining name length and current input block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NameWordBlock<const WORDS: usize> {
    /// Words presented to the selected compression function.
    words: [u32; WORDS],
}

impl<const WORDS: usize> NameWordBlock<WORDS> {
    /// Encodes one block beginning at `start`, padding it with the remaining byte count.
    fn at(bytes: &[u8], start: usize, encoding: NameByteEncoding) -> Self {
        let remaining = bytes.len().saturating_sub(start);
        let remaining_word = u32::try_from(remaining).unwrap_or(u32::MAX);
        let padding = remaining_word.wrapping_mul(0x0101_0101);
        let block_limit = remaining.min(WORDS.saturating_mul(4));
        let words = array::from_fn(|word_index| {
            let word_start = word_index.saturating_mul(4);
            if word_start >= block_limit {
                return padding;
            }
            let mut value = padding;
            for byte_in_word in 0..4_usize {
                let relative = word_start.saturating_add(byte_in_word);
                if relative >= block_limit {
                    break;
                }
                let absolute = start.saturating_add(relative);
                if let Some(byte) = bytes.get(absolute) {
                    value = encoding.value(*byte).wrapping_add(value.wrapping_shl(8));
                }
            }
            value
        });
        Self { words }
    }
}

/// Four-word chaining state shared by the seeded directory hash algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HashState {
    /// First chaining word.
    a: u32,
    /// Second chaining word.
    b: u32,
    /// Third chaining word.
    c: u32,
    /// Fourth chaining word.
    d: u32,
}

impl HashState {
    /// Constructs state from the four format-order seed words.
    const fn from_words(words: [u32; 4]) -> Self {
        let [a, b, c, d] = words;
        Self { a, b, c, d }
    }

    /// Adds one half-MD4 compression result into the chaining state.
    fn compress_half_md4(&mut self, input: NameWordBlock<8>) {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = input.words;
        let mut working = *self;
        working.apply_half_md4_round(
            HalfMd4Mix::Choice,
            [x0, x1, x2, x3, x4, x5, x6, x7],
            [3, 7, 11, 19, 3, 7, 11, 19],
            0,
        );
        working.apply_half_md4_round(
            HalfMd4Mix::Majority,
            [x1, x3, x5, x7, x0, x2, x4, x6],
            [3, 5, 9, 13, 3, 5, 9, 13],
            0x5a82_7999,
        );
        working.apply_half_md4_round(
            HalfMd4Mix::Parity,
            [x3, x7, x2, x6, x1, x5, x0, x4],
            [3, 9, 11, 15, 3, 9, 11, 15],
            0x6ed9_eba1,
        );
        self.a = self.a.wrapping_add(working.a);
        self.b = self.b.wrapping_add(working.b);
        self.c = self.c.wrapping_add(working.c);
        self.d = self.d.wrapping_add(working.d);
    }

    /// Applies one eight-step half-MD4 schedule to the working words.
    fn apply_half_md4_round(
        &mut self,
        mixing: HalfMd4Mix,
        messages: [u32; 8],
        rotations: [u32; 8],
        bias: u32,
    ) {
        for ((target, message), rotation) in
            LANE_UPDATE_ORDER.into_iter().zip(messages).zip(rotations)
        {
            let (current, first, second, third) = self.arguments(target);
            let next = current
                .wrapping_add(mixing.combine(first, second, third))
                .wrapping_add(message)
                .wrapping_add(bias)
                .rotate_left(rotation);
            self.write(target, next);
        }
    }

    /// Adds one 16-round TEA compression result into the first two chaining words.
    fn compress_tea(&mut self, input: NameWordBlock<4>) {
        let [key0, key1, key2, key3] = input.words;
        let mut left = self.a;
        let mut right = self.b;
        let mut sum = 0_u32;
        for _ in 0..16 {
            sum = sum.wrapping_add(TEA_ROUND_INCREMENT);
            left = left.wrapping_add(
                right.wrapping_shl(4).wrapping_add(key0)
                    ^ right.wrapping_add(sum)
                    ^ right.wrapping_shr(5).wrapping_add(key1),
            );
            right = right.wrapping_add(
                left.wrapping_shl(4).wrapping_add(key2)
                    ^ left.wrapping_add(sum)
                    ^ left.wrapping_shr(5).wrapping_add(key3),
            );
        }
        self.a = self.a.wrapping_add(left);
        self.b = self.b.wrapping_add(right);
    }

    /// Returns the current lane followed by its three cyclic inputs.
    const fn arguments(self, target: Lane) -> (u32, u32, u32, u32) {
        match target {
            Lane::A => (self.a, self.b, self.c, self.d),
            Lane::B => (self.b, self.c, self.d, self.a),
            Lane::C => (self.c, self.d, self.a, self.b),
            Lane::D => (self.d, self.a, self.b, self.c),
        }
    }

    /// Replaces one working lane selected by the fixed round schedule.
    const fn write(&mut self, target: Lane, value: u32) {
        match target {
            Lane::A => self.a = value,
            Lane::B => self.b = value,
            Lane::C => self.c = value,
            Lane::D => self.d = value,
        }
    }
}

/// One of the four working words updated by a half-MD4 step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
    /// First word.
    A,
    /// Second word.
    B,
    /// Third word.
    C,
    /// Fourth word.
    D,
}

/// Boolean mixing rule used by one half-MD4 round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HalfMd4Mix {
    /// Selects between the second and third inputs using the first.
    Choice,
    /// Selects bits held by at least two inputs.
    Majority,
    /// Computes the parity of all three inputs.
    Parity,
}

impl HalfMd4Mix {
    /// Combines three working words according to this round's rule.
    const fn combine(self, first: u32, second: u32, third: u32) -> u32 {
        match self {
            Self::Choice => (first & second) | (!first & third),
            Self::Majority => (first & second) | (first & third) | (second & third),
            Self::Parity => first ^ second ^ third,
        }
    }
}

/// Computes the legacy two-accumulator directory-name hash.
fn rolling_hash(bytes: &[u8], encoding: NameByteEncoding) -> (u32, u32) {
    let (current, _) = bytes.iter().fold(
        (0x12a3_fe2d_u32, 0x37ab_e8f9_u32),
        |(current, previous), byte| {
            let candidate =
                previous.wrapping_add(current ^ encoding.value(*byte).wrapping_mul(7_152_373));
            let next = if candidate & 0x8000_0000 == 0 {
                candidate
            } else {
                candidate.wrapping_sub(0x7fff_ffff)
            };
            (next, current)
        },
    );
    (current.wrapping_shl(1), 0)
}

#[cfg(test)]
mod tests {
    //! Black-box known-answer coverage for the ext4 directory-hash boundary.

    use alloc::vec;

    use super::{DirectoryHash, DirectoryHashScheme};
    use crate::disk_format::superblock::{DirectoryHashSeed, DirectoryHashVersion};
    use crate::platform::name::Ext4Name;

    /// Seed supplied to the independent e2fsprogs `debugfs dx_hash` oracle.
    const ORACLE_SEED: DirectoryHashSeed =
        DirectoryHashSeed::from_words([0x0403_0201, 0x0807_0605, 0x0c0b_0a09, 0x100f_0e0d]);

    /// # Panics
    ///
    /// Panics when signed and unsigned algorithms diverge from independently observed high-byte
    /// results.
    #[test]
    fn all_versions_match_high_byte_known_answers() {
        let Ok(name) = Ext4Name::from_disk(&[0x80, b'x']) else {
            return;
        };
        let cases = [
            (
                DirectoryHashVersion::Legacy,
                DirectoryHash {
                    major: 0x65ea_0956,
                    minor: 0,
                },
            ),
            (
                DirectoryHashVersion::HalfMd4,
                DirectoryHash {
                    major: 0xdc70_7c86,
                    minor: 0x60a8_887b,
                },
            ),
            (
                DirectoryHashVersion::Tea,
                DirectoryHash {
                    major: 0x1115_3a44,
                    minor: 0x7023_4016,
                },
            ),
            (
                DirectoryHashVersion::LegacyUnsigned,
                DirectoryHash {
                    major: 0xf734_1b56,
                    minor: 0,
                },
            ),
            (
                DirectoryHashVersion::HalfMd4Unsigned,
                DirectoryHash {
                    major: 0xed95_09f8,
                    minor: 0x76dd_19a1,
                },
            ),
            (
                DirectoryHashVersion::TeaUnsigned,
                DirectoryHash {
                    major: 0xdfb6_ad00,
                    minor: 0xcd05_b7a7,
                },
            ),
        ];
        for (version, expected) in cases {
            assert_eq!(
                DirectoryHashScheme::from_metadata(ORACLE_SEED, version).hash(&name),
                expected,
                "version {version:?}"
            );
        }
    }

    /// # Panics
    ///
    /// Panics when either block compressor stops honoring the name-length transition around its
    /// input width.
    #[test]
    fn block_boundaries_match_known_answers() {
        let cases = [
            (DirectoryHashVersion::Tea, 15, 0x6e56_3772, 0xef88_3696),
            (DirectoryHashVersion::Tea, 16, 0x4325_a512, 0x34c3_9657),
            (DirectoryHashVersion::Tea, 17, 0xc4b7_b762, 0xe449_15cc),
            (DirectoryHashVersion::HalfMd4, 31, 0x762e_6440, 0xeb1f_c23b),
            (DirectoryHashVersion::HalfMd4, 32, 0xbc1d_a53a, 0x0757_10a8),
            (DirectoryHashVersion::HalfMd4, 33, 0x3001_1dd6, 0x553a_1a34),
        ];
        for (version, length, major, minor) in cases {
            let bytes = vec![b'x'; length];
            let Ok(name) = Ext4Name::new(&bytes) else {
                return;
            };
            assert_eq!(
                DirectoryHashScheme::from_metadata(ORACLE_SEED, version).hash(&name),
                DirectoryHash { major, minor },
                "version {version:?}, length {length}"
            );
        }
    }

    /// # Panics
    ///
    /// Panics when full ext4 component length is not processed across every compression block.
    #[test]
    fn maximum_name_length_matches_known_answers() {
        let bytes = vec![b'x'; 255];
        let Ok(name) = Ext4Name::new(&bytes) else {
            return;
        };
        let cases = [
            (
                DirectoryHashVersion::Legacy,
                DirectoryHash {
                    major: 0x3055_7da6,
                    minor: 0,
                },
            ),
            (
                DirectoryHashVersion::HalfMd4,
                DirectoryHash {
                    major: 0xac45_f49a,
                    minor: 0x874d_addc,
                },
            ),
            (
                DirectoryHashVersion::Tea,
                DirectoryHash {
                    major: 0x7ba0_0f18,
                    minor: 0xcaea_b6ab,
                },
            ),
        ];
        for (version, expected) in cases {
            assert_eq!(
                DirectoryHashScheme::from_metadata(ORACLE_SEED, version).hash(&name),
                expected
            );
        }
    }
}

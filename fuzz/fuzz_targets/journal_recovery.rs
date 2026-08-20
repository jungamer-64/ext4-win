#![no_main]

use ext4_win_fuzz::{MAX_INPUT_BYTES, assert_deterministic_mount};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Some(length_bytes) = data.get(..4) else {
        return;
    };
    let Ok(raw_length) = <[u8; 4]>::try_from(length_bytes) else {
        return;
    };
    let Ok(filesystem_length) = usize::try_from(u32::from_le_bytes(raw_length)) else {
        return;
    };
    let Some(payload) = data.get(4..) else {
        return;
    };
    let Some(filesystem) = payload.get(..filesystem_length) else {
        return;
    };
    let Some(journal) = payload.get(filesystem_length..) else {
        return;
    };
    assert_deterministic_mount(filesystem, Some(journal));
});

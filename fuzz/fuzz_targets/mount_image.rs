#![no_main]

use ext4_win_fuzz::{MAX_INPUT_BYTES, assert_deterministic_mount};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= MAX_INPUT_BYTES {
        assert_deterministic_mount(data, None);
    }
});

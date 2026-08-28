/// # Panics
///
/// Panics when transfer windows fail to cover the exact request in bounded, ordered chunks.
#[test]
fn data_transfer_windows_partition_the_exact_request() {
    let total_value = super::MAX_DATA_TRANSFER_WINDOW_BYTES
        .saturating_mul(2)
        .saturating_add(17);
    let Some(total) = core::num::NonZeroUsize::new(total_value) else {
        return;
    };
    let mut windows = super::DataTransferWindows::new(total);
    assert_eq!(
        windows.snapshot_capacity(),
        super::MAX_DATA_TRANSFER_WINDOW_BYTES
    );

    for (expected_offset, expected_length) in [
        (0, super::MAX_DATA_TRANSFER_WINDOW_BYTES),
        (
            super::MAX_DATA_TRANSFER_WINDOW_BYTES,
            super::MAX_DATA_TRANSFER_WINDOW_BYTES,
        ),
        (super::MAX_DATA_TRANSFER_WINDOW_BYTES.saturating_mul(2), 17),
    ] {
        let window = windows.next_window();
        assert!(window.is_ok());
        if let Ok(Some(window)) = window {
            assert_eq!(window.offset(), expected_offset);
            assert_eq!(window.length(), expected_length);
        } else {
            return;
        }
    }
    assert_eq!(windows.next_window(), Ok(None));
    assert_eq!(windows.completed(), total_value);

    let Some(one_byte) = core::num::NonZeroUsize::new(1) else {
        return;
    };
    let mut minimum = super::DataTransferWindows::new(one_byte);
    assert_eq!(minimum.snapshot_capacity(), 1);
    assert_eq!(
        minimum.next_window(),
        Ok(Some(super::DataTransferWindow {
            offset: 0,
            length: one_byte,
        }))
    );
    assert_eq!(minimum.next_window(), Ok(None));
}

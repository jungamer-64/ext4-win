use crate::error::{Error, Result};

pub fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = fixed::<2>(bytes, offset)?;
    Ok(u16::from_le_bytes(raw))
}

pub fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = fixed::<4>(bytes, offset)?;
    Ok(u32::from_le_bytes(raw))
}

pub fn be_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = fixed::<4>(bytes, offset)?;
    Ok(u32::from_be_bytes(raw))
}

pub fn put_le_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

pub fn put_le_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

pub fn put_be_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    put_fixed(bytes, offset, &value.to_be_bytes())
}

fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(Error::ArithmeticOverflow)?;
    let slice = bytes.get(offset..end).ok_or(Error::TruncatedStructure)?;
    let mut raw = [0_u8; N];
    raw.copy_from_slice(slice);
    Ok(raw)
}

fn put_fixed(bytes: &mut [u8], offset: usize, source: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(source.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let target = bytes
        .get_mut(offset..end)
        .ok_or(Error::TruncatedStructure)?;
    target.copy_from_slice(source);
    Ok(())
}

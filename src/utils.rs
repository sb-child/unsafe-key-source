// channel id &[u8] to u32
pub(crate) fn channel_id_to_u32(c: &[u8]) -> u32 {
    if c.len() != 4 {
        return 0;
    }
    <byteorder::LittleEndian as byteorder::ByteOrder>::read_u32(c)
}
// channel id u32 to [u8; 4]
pub(crate) fn channel_id_to_array(c: u32) -> [u8; 4] {
    let mut r = [0u8; 4];
    <byteorder::LittleEndian as byteorder::ByteOrder>::write_u32(&mut r, c);
    r
}
// channel id &[u8] to u32
pub(crate) fn data_len_to_u16(c: &[u8]) -> u16 {
    if c.len() != 2 {
        return 0;
    }
    <byteorder::LittleEndian as byteorder::ByteOrder>::read_u16(c)
}
// channel id u32 to [u8; 4]
pub(crate) fn data_len_to_array(c: u16) -> [u8; 2] {
    let mut r = [0u8; 2];
    <byteorder::LittleEndian as byteorder::ByteOrder>::write_u16(&mut r, c);
    r
}

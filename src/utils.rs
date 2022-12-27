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

/*
    unsafe{key}: The most unsafe usb security key that support FIDO2 protocol
    Copyright (C) 2022 sb-child

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
    let c2 = [c[1], c[0]];
    <byteorder::LittleEndian as byteorder::ByteOrder>::read_u16(&c2)
}
// channel id u32 to [u8; 4]
pub(crate) fn data_len_to_array(c: u16) -> [u8; 2] {
    let mut r = [0u8; 2];
    <byteorder::LittleEndian as byteorder::ByteOrder>::write_u16(&mut r, c);
    let r2 = [r[1], r[0]];
    r2
}

pub(crate) fn set_bit_u128(a: &mut u128, index: u8) {
    let mask = 1 << index;
    *a |= mask;
}

pub(crate) fn clear_bit_u128(a: &mut u128, index: u8) {
    let mask = 1 << index;
    *a &= !mask;
}

pub(crate) fn read_bit_u128(a: &u128, index: u8) -> bool {
    let mask = 1 << index;
    *a & mask == mask
}

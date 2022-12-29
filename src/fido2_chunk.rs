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

use crate::utils::set_bit_u128;

#[derive(Debug)]
pub(crate) struct FIDO2ChunkMerger {
    pub first_packet_length: u8,
    pub first_packet_received: bool,
    pub seq_received: u128,
    pub data_length: u16,
}
impl FIDO2ChunkMerger {
    pub fn new(data_length: u16, first_packet_length: u8) -> FIDO2ChunkMerger {
        // [first len: first_packet_length, max=57] [chunk 0: 59] [chunk 1: 59] ... [chunk 127: 59]
        // if data_length <= first_packet_length, no chunks needed
        FIDO2ChunkMerger {
            first_packet_received: false,
            seq_received: 0,
            data_length,
            first_packet_length,
        }
    }
    fn mark_first_packet_received(&mut self) {
        self.first_packet_received = true;
    }
    fn mark_chunk_packet_received(&mut self, index: u8) {
        set_bit_u128(&mut self.seq_received, index);
    }
    pub fn is_done(&self) -> bool {
        self.first_packet_received && self.seq_received == (1u128 << self.data_length as usize) - 1
    }
    pub fn apply(&mut self, buffer: &mut [u8], data: &[u8], seq_id: u8) {
        // seq_id > 127: first packet
        if seq_id > 127 {
            // first packet
            let first_len = core::cmp::min(self.first_packet_length as usize, data.len());
            let _ = &mut buffer[..first_len].copy_from_slice(&data[..first_len]);
            self.mark_first_packet_received();
        } else {
            // chunk packet
            let chunk_len = core::cmp::min(59, data.len());
            let _ = &mut buffer[seq_id as usize * 59 + self.first_packet_length as usize
                ..seq_id as usize * 59 + self.first_packet_length as usize + chunk_len]
                .copy_from_slice(&data[..chunk_len]);
            self.mark_chunk_packet_received(seq_id);
        }
    }
}

#[derive(Debug)]
pub(crate) struct FIDO2ChunkSpliter {
    pub data_length: u16,
    pub first_packet_length: u8,
    pub chunks_num: u8,
}
impl FIDO2ChunkSpliter {
    pub fn new(data_length: u16, first_packet_length: u8) -> FIDO2ChunkSpliter {
        let chunks_num = if data_length <= first_packet_length as u16 {
            0
        } else {
            ((data_length - first_packet_length as u16) / 59 + 1) as u8
        };
        FIDO2ChunkSpliter {
            data_length,
            first_packet_length,
            chunks_num,
        }
    }
    pub fn apply(&self, buffer: &[u8], data: &mut [u8], seq_id: u8) {
        // seq_id > 127: first packet
        if seq_id > 127 {
            // first packet
            let first_len = core::cmp::min(self.first_packet_length as usize, data.len());
            let _ = &mut data[..first_len].copy_from_slice(&buffer[..first_len]);
        } else {
            // chunk packet
            let chunk_len = core::cmp::min(59, data.len());
            let _ = &mut data[..chunk_len].copy_from_slice(
                &buffer[seq_id as usize * 59 + self.first_packet_length as usize
                    ..seq_id as usize * 59 + self.first_packet_length as usize + chunk_len],
            );
        }
    }
    pub fn chunks(&self) -> u8 {
        self.chunks_num
    }
}

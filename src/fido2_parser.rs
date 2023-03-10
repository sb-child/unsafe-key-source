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

use num_enum::TryFromPrimitive;

use crate::{
    consts::{BUILD_VERSION, FIDO2_MAX_DATA_LENGTH, MAJOR_VERSION, MINOR_VERSION},
    fido2_internal_error::FIDO2InternalError,
    utils::{channel_id_to_array, channel_id_to_u32, data_len_to_array, data_len_to_u16},
};

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum FIDO2PacketCommand {
    CtapHIDMsg = 0x03,
    CtapHIDCbor = 0x10,
    CtapHIDInit = 0x06,
    CtapHIDPing = 0x01,
    CtapHIDCancel = 0x11,
    CtapHIDError = 0x3F,
    CtapHIDKeepalive = 0x3B,
    CtapHIDWink = 0x08,
    CtapHIDLock = 0x04,
}
// packet struct
#[derive(Debug)]
pub(crate) struct FIDO2PacketBuilder {
    pub channel_id: u32,
    pub packet_type: Option<FIDO2PacketCommand>,
    pub seq_id: u8,
    pub data_length: u16,
    pub is_seq: bool,
    pub data: [u8; 64 - 5],
}
impl FIDO2PacketBuilder {
    pub fn new_from_raw_packet(packet: [u8; 64]) -> Result<FIDO2PacketBuilder, FIDO2InternalError> {
        // packet 00 00 00 00
        // index  00 01 02 03
        let channel_id_raw = &packet[0..4];
        let channel_id = channel_id_to_u32(channel_id_raw);
        if channel_id == 0x00000000 {
            return Err(FIDO2InternalError::ReversedChannelError);
        }
        let packet_type_raw = packet[4];
        let mut packet_type = FIDO2PacketCommand::CtapHIDInit;
        let data_length_raw = data_len_to_u16(&packet[5..=6]);
        let mut data_length: u16 = 0;
        let mut is_seq = false;
        let mut data = [0u8; 64 - 5];
        // 0b0_______ seq
        // 0b1_______ command
        if packet_type_raw & 0b10000000 == 0b10000000 {
            // command
            // bound check
            if data_length_raw > FIDO2_MAX_DATA_LENGTH as u16 {
                return Err(FIDO2InternalError::DataLengthError);
            }
            // select data
            if data_length_raw > 1 {
                let data_raw: &[u8] =
                    &packet[7..];
                for (k, v) in data_raw.iter().enumerate() {
                    data[k] = *v;
                }
                data_length = data_length_raw;
            }
            // convert
            let result = FIDO2PacketCommand::try_from(packet_type_raw & 0b01111111);
            if result.is_ok() {
                packet_type = result.unwrap();
            } else {
                return Err(FIDO2InternalError::CommandNotFoundError);
            }
        } else {
            // seq
            is_seq = true;
            data_length = 64 - 5;
            let data_raw: &[u8] = &packet[5..];
            for (k, v) in data_raw.iter().enumerate() {
                data[k] = *v;
            }
        }
        Ok(FIDO2PacketBuilder {
            channel_id,
            packet_type: if is_seq { None } else { Some(packet_type) },
            data_length,
            is_seq,
            data,
            seq_id: if is_seq { packet_type_raw } else { 0xff },
        })
    }
    pub fn pack(self) -> Result<[u8; 64], FIDO2InternalError> {
        let mut packet = [0u8; 64];
        // channel id
        let channel_id_raw = channel_id_to_array(self.channel_id);
        for (k, v) in channel_id_raw.iter().enumerate() {
            packet[k] = *v;
        }
        // packet type
        let packet_type_raw = if self.is_seq {
            self.seq_id
        } else {
            (self.packet_type.unwrap() as u8) + 0b10000000
        };
        packet[4] = packet_type_raw;
        // data(seq)
        if self.is_seq {
            for (k, v) in self.data.iter().enumerate() {
                packet[k + 5] = *v;
            }
            return Ok(packet);
        }
        // BCNTH, BCNTL
        let packet_len_arr = data_len_to_array(self.data_length);
        packet[5] = packet_len_arr[0];
        packet[6] = packet_len_arr[1];
        // data
        for (k, v) in self.data[..self.data_length as usize].iter().enumerate() {
            packet[k + 7] = *v;
        }
        return Ok(packet);
    }
}

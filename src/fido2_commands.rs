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
};

// Trait

pub trait FIDO2PacketCommandResponse {
    fn apply(self, arr: &mut [u8]) -> Option<u16>;
}

// Ping

#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandPingRequest<'a> {
    pub data: &'a [u8],
}
impl<'a> FIDO2PacketCommandPingRequest<'a> {
    pub fn unpack(packet: &[u8]) -> Result<FIDO2PacketCommandPingRequest, FIDO2InternalError> {
        Ok(FIDO2PacketCommandPingRequest { data: packet })
    }
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandPingResponse<'a> {
    pub data: &'a [u8],
}
impl<'a> FIDO2PacketCommandPingResponse<'a> {
    fn new(data: &'a [u8]) -> FIDO2PacketCommandPingResponse<'a> {
        FIDO2PacketCommandPingResponse { data }
    }
}
impl<'a> FIDO2PacketCommandResponse for FIDO2PacketCommandPingResponse<'a> {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        let required_size = self.data.len();
        if arr.len() < required_size {
            return None;
        }
        for (k, v) in self.data[..required_size].iter().enumerate() {
            arr[k] = *v;
        }
        return Some(required_size as u16);
    }
}

// Cancel

#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandCancelRequest {}
impl FIDO2PacketCommandCancelRequest {
    pub fn unpack() -> Result<FIDO2PacketCommandCancelRequest, FIDO2InternalError> {
        Ok(FIDO2PacketCommandCancelRequest {})
    }
}

// Error

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum FIDO2ErrorCode {
    ErrInvalidCmd = 0x01,     //????????????????????????
    ErrInvalidPar = 0x02,     //????????????????????????
    ErrInvalidLen = 0x03,     //????????????????????? (BCNT) ??????
    ErrInvalidSeq = 0x04,     //???????????????????????????
    ErrMsgTimeout = 0x05,     //????????????
    ErrChannelBusy = 0x06, //???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    ErrLockRequired = 0x0A, //????????????????????????
    ErrInvalidChannel = 0x0B, //CID ??????
    ErrOther = 0x7F,       //??????????????????
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandErrorResponse {
    pub code: FIDO2ErrorCode,
}
impl FIDO2PacketCommandErrorResponse {
    pub fn new(code: FIDO2ErrorCode) -> FIDO2PacketCommandErrorResponse {
        FIDO2PacketCommandErrorResponse { code }
    }
}
impl FIDO2PacketCommandResponse for FIDO2PacketCommandErrorResponse {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        let required_size = 1;
        if arr.len() < required_size {
            return None;
        }
        arr[1] = self.code as u8;
        return Some(required_size as u16);
    }
}

// KeepAlive

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum FIDO2KeepAliveCode {
    StatusProcessing = 1, //???????????????????????????????????????
    StatusUpNeeded = 2,   //???????????????????????????????????????
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandKeepAliveResponse {
    pub code: FIDO2KeepAliveCode,
}
impl FIDO2PacketCommandKeepAliveResponse {
    pub fn new(code: FIDO2KeepAliveCode) -> FIDO2PacketCommandKeepAliveResponse {
        FIDO2PacketCommandKeepAliveResponse { code }
    }
}
impl FIDO2PacketCommandResponse for FIDO2PacketCommandKeepAliveResponse {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        let required_size = 1;
        if arr.len() < required_size {
            return None;
        }
        arr[1] = self.code as u8;
        return Some(required_size as u16);
    }
}

// Init

#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandInitRequest {
    pub random: [u8; 8],
}
impl FIDO2PacketCommandInitRequest {
    pub fn unpack(packet: &[u8]) -> Result<FIDO2PacketCommandInitRequest, FIDO2InternalError> {
        if packet.len() < 8 {
            return Err(FIDO2InternalError::DataLengthError);
        }
        Ok(FIDO2PacketCommandInitRequest {
            random: packet[..8].try_into().unwrap(),
        })
    }
}
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum FIDO2Capabilities {
    CapabilityWink = 0x01, // set 1 enable wink
    CapabilityCbor = 0x04, // set 1 enable cbor
    CapabilityNmsg = 0x08, // set 1 disable nmsg
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandInitResponse {
    pub random: [u8; 8],
    pub channel_id: [u8; 4],
    pub protocol_version: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub build_version: u8,
    pub capabilities_flag: u8,
}
impl FIDO2PacketCommandInitResponse {
    pub fn new(random: [u8; 8], channel_id: [u8; 4]) -> FIDO2PacketCommandInitResponse {
        FIDO2PacketCommandInitResponse {
            random,
            channel_id,
            protocol_version: 2,
            major_version: MAJOR_VERSION,
            minor_version: MINOR_VERSION,
            build_version: BUILD_VERSION,
            capabilities_flag: (FIDO2Capabilities::CapabilityWink as u8
                | FIDO2Capabilities::CapabilityNmsg as u8),
        }
    }
}
impl FIDO2PacketCommandResponse for FIDO2PacketCommandInitResponse {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        let required_size = 17;
        if arr.len() < required_size {
            return None;
        }
        // 8 bytes random
        for (k, v) in self.random.iter().enumerate() {
            arr[k] = *v;
        }
        // 4 bytes channel id
        for (k, v) in self.channel_id.iter().enumerate() {
            arr[k + 8] = *v;
        }
        // CTAPHID version
        arr[12] = self.protocol_version;
        // Major device version number
        arr[13] = self.major_version;
        // Minor device version number
        arr[14] = self.minor_version;
        // Build device version number
        arr[15] = self.build_version;
        // Capabilities flags
        // CAPABILITY_WINK 0x01 set 1 enable
        // CAPABILITY_CBOR 0x04 set 1 enable
        // CAPABILITY_NMSG 0x08 set 1 disable
        arr[16] = self.capabilities_flag;
        return Some(required_size as u16);
    }
}

// Wink

#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandWinkRequest {}
impl FIDO2PacketCommandWinkRequest {
    pub fn unpack() -> Result<FIDO2PacketCommandWinkRequest, FIDO2InternalError> {
        Ok(FIDO2PacketCommandWinkRequest {})
    }
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandWinkResponse {}
impl FIDO2PacketCommandWinkResponse {
    pub fn new() -> FIDO2PacketCommandWinkResponse {
        FIDO2PacketCommandWinkResponse {}
    }
}
impl FIDO2PacketCommandResponse for FIDO2PacketCommandWinkResponse {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        return Some(0);
    }
}

// Lock

#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandLockRequest {
    lock_time: u8,
}
impl FIDO2PacketCommandLockRequest {
    pub fn unpack(packet: &[u8]) -> Result<FIDO2PacketCommandLockRequest, FIDO2InternalError> {
        if packet.len() < 1 {
            return Err(FIDO2InternalError::DataLengthError);
        }
        Ok(FIDO2PacketCommandLockRequest {
            lock_time: packet[0],
        })
    }
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandLockResponse {}
impl FIDO2PacketCommandLockResponse {
    pub fn new() -> FIDO2PacketCommandLockResponse {
        FIDO2PacketCommandLockResponse {}
    }
}
impl FIDO2PacketCommandResponse for FIDO2PacketCommandLockResponse {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        return Some(0);
    }
}

// Msg (u2f)

#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandMsgRequest<'a> {
    pub command: u8,
    pub data: &'a [u8],
}
impl<'a> FIDO2PacketCommandMsgRequest<'a> {
    pub fn unpack(packet: &[u8]) -> Result<FIDO2PacketCommandMsgRequest, FIDO2InternalError> {
        if packet.len() < 1 {
            return Err(FIDO2InternalError::DataLengthError);
        }
        let command = packet[0];
        let data = &packet[1..];
        Ok(FIDO2PacketCommandMsgRequest { command, data })
    }
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandMsgResponse<'a> {
    pub status_code: u8,
    pub data: &'a [u8],
}
impl<'a> FIDO2PacketCommandMsgResponse<'a> {
    pub fn new(status_code: u8, data: &'a [u8]) -> FIDO2PacketCommandMsgResponse {
        FIDO2PacketCommandMsgResponse { status_code, data }
    }
}
impl<'a> FIDO2PacketCommandResponse for FIDO2PacketCommandMsgResponse<'a> {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        let required_size = self.data.len() + 1;
        if arr.len() < required_size {
            return None;
        }
        arr[0] = self.status_code;
        for (k, v) in self.data.iter().enumerate() {
            arr[k + 1] = *v;
        }
        return Some(required_size as u16);
    }
}

// Cbor

#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandCborRequest<'a> {
    pub command: u8,
    pub data: &'a [u8],
}
impl<'a> FIDO2PacketCommandCborRequest<'a> {
    pub fn unpack(packet: &[u8]) -> Result<FIDO2PacketCommandCborRequest, FIDO2InternalError> {
        if packet.len() < 1 {
            return Err(FIDO2InternalError::DataLengthError);
        }
        let command = packet[0];
        let data = &packet[1..];
        Ok(FIDO2PacketCommandCborRequest { command, data })
    }
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandCborResponse<'a> {
    pub status_code: u8,
    pub data: &'a [u8],
}
impl<'a> FIDO2PacketCommandCborResponse<'a> {
    pub fn new(status_code: u8, data: &'a [u8]) -> FIDO2PacketCommandCborResponse {
        FIDO2PacketCommandCborResponse { status_code, data }
    }
}
impl<'a> FIDO2PacketCommandResponse for FIDO2PacketCommandCborResponse<'a> {
    fn apply(self, arr: &mut [u8]) -> Option<u16> {
        let required_size = self.data.len() + 1;
        if arr.len() < required_size {
            return None;
        }
        arr[0] = self.status_code;
        for (k, v) in self.data.iter().enumerate() {
            arr[k + 1] = *v;
        }
        return Some(required_size as u16);
    }
}

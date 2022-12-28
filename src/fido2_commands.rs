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
    pub fn new(data: &[u8]) -> FIDO2PacketCommandPingResponse {
        FIDO2PacketCommandPingResponse { data }
    }
    pub fn pack(self) -> &'a [u8] {
        self.data
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
    ErrInvalidCmd = 0x01,     //请求中的命令无效
    ErrInvalidPar = 0x02,     //请求中的参数无效
    ErrInvalidLen = 0x03,     //请求的长度字段 (BCNT) 无效
    ErrInvalidSeq = 0x04,     //序列与预期值不匹配
    ErrMsgTimeout = 0x05,     //消息超时
    ErrChannelBusy = 0x06, //设备正忙于请求通道。客户端应该在短暂延迟后重试请求。请注意，如果命令不再相关，客户端可能会中止事务
    ErrLockRequired = 0x0A, //命令需要频道锁定
    ErrInvalidChannel = 0x0B, //CID 无效
    ErrOther = 0x7F,       //未指定的错误
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandErrorResponse {
    pub code: FIDO2ErrorCode,
}
impl FIDO2PacketCommandErrorResponse {
    pub fn new(code: FIDO2ErrorCode) -> FIDO2PacketCommandErrorResponse {
        FIDO2PacketCommandErrorResponse { code }
    }
    pub fn pack(self) -> [u8; 1] {
        let mut packet = [0u8; 1];
        packet[1] = self.code as u8;
        packet
    }
}

// KeepAlive

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum FIDO2KeepAliveCode {
    StatusProcessing = 1, //身份验证器仍在处理当前请求
    StatusUpNeeded = 2,   //身份验证器正在等待用户出现
}
#[derive(Debug)]
pub(crate) struct FIDO2PacketCommandKeepAliveResponse {
    pub code: FIDO2KeepAliveCode,
}
impl FIDO2PacketCommandKeepAliveResponse {
    pub fn new(code: FIDO2KeepAliveCode) -> FIDO2PacketCommandKeepAliveResponse {
        FIDO2PacketCommandKeepAliveResponse { code }
    }
    pub fn pack(self) -> [u8; 1] {
        let mut packet = [0u8; 1];
        packet[1] = self.code as u8;
        packet
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
    pub fn apply(self, arr: &mut [u8]) -> Option<u16> {
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
    pub fn apply(self, arr: &mut [u8]) -> Option<u16> {
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
    pub fn apply(self, arr: &mut [u8]) -> Option<u16> {
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
    pub fn apply(self, arr: &mut [u8]) -> Option<u16> {
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
    pub fn apply(self, arr: &mut [u8]) -> Option<u16> {
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

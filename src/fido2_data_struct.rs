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
    pub fn pack(self) -> [u8; 17] {
        let mut packet = [0u8; 17];
        // 8 bytes random
        for (k, v) in self.random.iter().enumerate() {
            packet[k] = *v;
        }
        // 4 bytes channel id
        for (k, v) in self.channel_id.iter().enumerate() {
            packet[k + 8] = *v;
        }
        // CTAPHID version
        packet[12] = self.protocol_version;
        // Major device version number
        packet[13] = self.major_version;
        // Minor device version number
        packet[14] = self.minor_version;
        // Build device version number
        packet[15] = self.build_version;
        // Capabilities flags
        // CAPABILITY_WINK 0x01 set 1 enable
        // CAPABILITY_CBOR 0x04 set 1 enable
        // CAPABILITY_NMSG 0x08 set 1 disable
        packet[16] = self.capabilities_flag;
        packet
    }
}

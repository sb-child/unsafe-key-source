pub(crate) const MAJOR_VERSION: u8 = 1;
pub(crate) const MINOR_VERSION: u8 = 0;
pub(crate) const BUILD_VERSION: u8 = 1;
pub(crate) const FIDO2_MAX_DATA_LENGTH: usize = 7609;
pub(crate) const FIDO2_MAX_NORMAL_PACKET_DATA_SIZE: usize = 64 - 7;
pub(crate) const FIDO2_MAX_CHUNK_PACKET_DATA_SIZE: usize = 64 - 5;
// protocol
pub(crate) const FIDO2_COMMAND_MSG_REQUEST_MAX_SIZE: usize = FIDO2_MAX_DATA_LENGTH;
pub(crate) const FIDO2_COMMAND_MSG_RESPONSE_MAX_SIZE: usize = FIDO2_MAX_DATA_LENGTH;

pub(crate) const FIDO2_COMMAND_CBOR_REQUEST_MAX_SIZE: usize = FIDO2_MAX_DATA_LENGTH;
pub(crate) const FIDO2_COMMAND_CBOR_RESPONSE_MAX_SIZE: usize = FIDO2_MAX_DATA_LENGTH;

pub(crate) const FIDO2_COMMAND_INIT_REQUEST_MAX_SIZE: usize = 8;
pub(crate) const FIDO2_COMMAND_INIT_RESPONSE_MAX_SIZE: usize = 17;

pub(crate) const FIDO2_COMMAND_PING_REQUEST_MAX_SIZE: usize = FIDO2_MAX_DATA_LENGTH;
pub(crate) const FIDO2_COMMAND_PING_RESPONSE_MAX_SIZE: usize = FIDO2_MAX_DATA_LENGTH;

pub(crate) const FIDO2_COMMAND_CANCEL_REQUEST_MAX_SIZE: usize = 0;
pub(crate) const FIDO2_COMMAND_CANCEL_RESPONSE_MAX_SIZE: usize = 1;

pub(crate) const FIDO2_COMMAND_KEEPALIVE_RESPONSE_MAX_SIZE: usize = 1;

pub(crate) const FIDO2_COMMAND_WINK_REQUEST_MAX_SIZE: usize = 0;
pub(crate) const FIDO2_COMMAND_WINK_RESPONSE_MAX_SIZE: usize = 0;

pub(crate) const FIDO2_COMMAND_LOCK_REQUEST_MAX_SIZE: usize = 1;
pub(crate) const FIDO2_COMMAND_LOCK_RESPONSE_MAX_SIZE: usize = 0;

use crate::consts::FIDO2_MAX_DATA_LENGTH;

#[derive(Debug)]
pub(crate) struct GlobalBuffer {
    pub request_buffer: [u8; FIDO2_MAX_DATA_LENGTH],
    pub response_buffer: [u8; FIDO2_MAX_DATA_LENGTH],
    pub request_buffer_data_len: u16,
    pub response_buffer_data_len: u16,
    pub request_buffer_done: bool,
    pub response_buffer_done: bool,
}
impl GlobalBuffer {
    pub fn new() -> GlobalBuffer {
        GlobalBuffer {
            request_buffer: [0u8; FIDO2_MAX_DATA_LENGTH],
            response_buffer: [0u8; FIDO2_MAX_DATA_LENGTH],
            request_buffer_data_len: 0,
            response_buffer_data_len: 0,
            request_buffer_done: false,
            response_buffer_done: false,
        }
    }
}

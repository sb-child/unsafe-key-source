use crate::consts::FIDO2_MAX_DATA_LENGTH;
use crate::FIDO2Commands::FIDO2PacketCommandResponse;

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
    pub fn apply_response_from(&mut self, resp: impl FIDO2PacketCommandResponse){
        let length = resp.apply(&mut self.response_buffer).unwrap();
        self.set_response_done(length);
    }
    pub fn set_request_done(&mut self, length: u16) {
        self.request_buffer_data_len = length;
        self.request_buffer_done = true;
    }
    pub fn set_response_done(&mut self, length: u16) {
        self.response_buffer_data_len = length;
        self.response_buffer_done = true;
    }
    pub fn get_request_pending(&self) -> bool {
        !self.request_buffer_done
    }
    pub fn get_response_pending(&self) -> bool {
        !self.response_buffer_done
    }
    pub fn clear_request(&mut self) {
        self.request_buffer_data_len = 0;
        self.request_buffer_done = false;
        self.request_buffer.fill(0u8);
    }
    pub fn clear_response(&mut self) {
        self.response_buffer_data_len = 0;
        self.response_buffer_done = false;
        self.response_buffer.fill(0u8);
    }
}

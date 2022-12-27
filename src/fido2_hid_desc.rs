use usbd_hid::{self, descriptor::generator_prelude::*};

#[gen_hid_descriptor(
    (collection = APPLICATION, usage_page = 0xF1D0, usage = 0x01) = {
        (usage = 0x01, usage_min = 0x00, usage_max = 0xff, logical_min = 0) = {
            #[item_settings data,variable] buff_in=input;
        };
        (usage = 0x81, usage_min = 0x00, usage_max = 0xff, logical_min = 0) = {
            #[item_settings data,variable] buff_out=output;
        };
    }
)]
pub(crate) struct FIDO2Report {
    buff_in: [u8; 64],
    buff_out: [u8; 64],
}

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

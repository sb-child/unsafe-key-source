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

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

#![no_main]
#![no_std]
#![allow(unused_imports)]

use num_enum::TryFromPrimitive;
// use panic_halt as _;
use build_time;
use byteorder;
use core::cell::RefCell;
use core::fmt::Write;
use core::ops::DerefMut;
use cortex_m::interrupt::Mutex;
use cortex_m_rt::entry;
use embedded_hal::digital::v2::{InputPin, IoPin, OutputPin};
use fugit::MicrosDuration;
use nb::block;
use num_enum::IntoPrimitive;
use panic_reset as _;
use stm32f1xx_hal::device::TIM1;
use stm32f1xx_hal::device::TIM2;
use stm32f1xx_hal::gpio::PinState;
use stm32f1xx_hal::i2c;
use stm32f1xx_hal::stm32::{self, interrupt, Interrupt};
use stm32f1xx_hal::timer::Event;
use stm32f1xx_hal::{afio::AfioExt, pac, usb};
use stm32f1xx_hal::{prelude::*, serial};
use usb_device::{self, prelude::*};
use usbd_hid::{self, descriptor::generator_prelude::*};

mod consts;
mod fido2_chunk;
mod fido2_commands;
mod fido2_hid_desc;
mod fido2_internal_error;
mod fido2_parser;
mod global_buffer;
mod utils;

use consts as ProjectConsts;
use fido2_chunk as FIDO2Chunk;
use fido2_commands as FIDO2Commands;
use fido2_hid_desc as FIDO2HID;
use fido2_internal_error as FIDO2Errors;
use fido2_parser as FIDO2Parser;
use global_buffer as GlobalBuffer;

use FIDO2Commands::FIDO2PacketCommandResponse;

static mut GLOBAL_TIMER: u128 = 0;
// static G_TIM: Mutex<RefCell<Option<stm32f1xx_hal::timer::CounterUs<TIM1>>>> =
//     Mutex::new(RefCell::new(None));

// #[interrupt]
// fn TIM1_UP() {
//     static mut STIM: Option<stm32f1xx_hal::timer::CounterUs<TIM1>> = None;
//     let tim = STIM.get_or_insert_with(|| {
//         cortex_m::interrupt::free(|cs| G_TIM.borrow(cs).replace(None).unwrap())
//     });
//     unsafe { GLOBAL_TIMER += 1 };
//     let _ = tim.wait();
// }
fn get_timer() -> u128 {
    unsafe { GLOBAL_TIMER }
}
fn add_timer() {
    unsafe {
        GLOBAL_TIMER += 1;
    }
}

#[entry]
fn main() -> ! {
    // hardware init
    let dp = pac::Peripherals::take().unwrap();
    let cp = cortex_m::Peripherals::take().unwrap();
    let rcc = dp.RCC.constrain();
    let mut flash = dp.FLASH.constrain();
    let clocks = rcc
        .cfgr
        .use_hse(8.MHz())
        .sysclk(72.MHz())
        .freeze(&mut flash.acr);
    let mut gpioa = dp.GPIOA.split();
    let mut gpiob = dp.GPIOB.split();
    let mut gpioc = dp.GPIOC.split();
    let mut gpiod = dp.GPIOD.split();
    let mut afio = dp.AFIO.constrain();
    let (pa15, pb3, pb4) = afio.mapr.disable_jtag(gpioa.pa15, gpiob.pb3, gpiob.pb4);
    // debug serial port
    let tx = gpioa.pa9.into_alternate_push_pull(&mut gpioa.crh);
    let rx = gpioa.pa10;
    let serial = serial::Serial::new(
        dp.USART1,
        (tx, rx),
        &mut afio.mapr,
        serial::Config::default().baudrate(115200.bps()),
        &clocks,
    );
    let (mut tx, rx) = serial.split();
    // build timestamp
    let _usb_serial_number = concat!(
        "Firmware v1 ",
        build_time::build_time_local!("%Y%m%d-%H%M%S%z")
    );
    // === function ===
    // channel ID
    // 0x00000000 is reversed, 0xffffffff is reserved for broadcast
    // id range available: 0x00001000(4096) ~ 0x0000100a(4106)
    let mut _fido2_channel_id_used = [false; 4106 - 4096];
    let _fido2_channel_id_offset = |cid: u32| -> usize { (0x00001000 + cid) as usize };
    let fido2_channel_create = |cid: u32| -> Option<u32> {
        if fido2_channel_reversed(cid) {
            return None;
        }
        // try to find a available id
        for (k, v) in _fido2_channel_id_used.iter().enumerate() {
            if !v {
                _fido2_channel_id_used[k] = true;
                return Some((k + 0x00001000) as u32);
            }
        }
        // id was full
        return None;
    };
    let fido2_channel_delete = |cid: u32| {
        if !(cid < 0x00001000 || cid > 0x0000100a) {
            _fido2_channel_id_used[_fido2_channel_id_offset(cid)] = false
        }
    };
    let fido2_channel_exists = |cid: u32| -> bool {
        if cid < 0x00001000 || cid > 0x0000100a {
            false
        } else if _fido2_channel_id_used[_fido2_channel_id_offset(cid)] {
            true
        } else {
            false
        }
    };
    fn fido2_channel_reversed(cid: u32) -> bool {
        cid == 0x00000000 || cid == 0xffffffff
    }
    // usb
    let mut usb_dp = gpioa.pa12.into_push_pull_output(&mut gpioa.crh);
    usb_dp.set_low();
    let hid_usb_port = usb::Peripheral {
        usb: dp.USB,
        pin_dm: gpioa.pa11,
        pin_dp: usb_dp.into_floating_input(&mut gpioa.crh),
    };
    let hid_usb_bus = usb::UsbBus::new(hid_usb_port);
    let mut hid_usb_ctrl =
        usbd_hid::hid_class::HIDClass::new(&hid_usb_bus, FIDO2HID::FIDO2Report::desc(), 60);
    let mut hid_usb_dev = UsbDeviceBuilder::new(&hid_usb_bus, UsbVidPid(0x7777, 0x0001))
        .manufacturer("GitHub @sb-child")
        .product("unsafe{key} Board v1.0")
        .serial_number(_usb_serial_number)
        .build();
    // global buffer
    let mut global_request_buffer = [0u8; ProjectConsts::FIDO2_MAX_DATA_LENGTH];
    let mut global_response_buffer = [0u8; ProjectConsts::FIDO2_MAX_DATA_LENGTH];
    // perpare flags
    let mut global_request_buffer_data_len = 0u16;
    let mut global_response_buffer_data_len = 0u16;
    let mut global_request_buffer_done = false;
    let mut global_response_buffer_done = false;
    // error generator
    fn _fido2_err_command_not_found() -> impl FIDO2Commands::FIDO2PacketCommandResponse {
        FIDO2Commands::FIDO2PacketCommandErrorResponse::new(
            FIDO2Commands::FIDO2ErrorCode::ErrInvalidCmd,
        )
    }
    fn _fido2_err_data_length() -> impl FIDO2Commands::FIDO2PacketCommandResponse {
        FIDO2Commands::FIDO2PacketCommandErrorResponse::new(
            FIDO2Commands::FIDO2ErrorCode::ErrInvalidLen,
        )
    }
    fn _fido2_err_reversed_channel() -> impl FIDO2Commands::FIDO2PacketCommandResponse {
        FIDO2Commands::FIDO2PacketCommandErrorResponse::new(
            FIDO2Commands::FIDO2ErrorCode::ErrInvalidChannel,
        )
    }
    // flags
    let mut _fido2_request_done = |length: u16| {
        global_request_buffer_data_len = length;
        global_request_buffer_done = true;
    };
    let mut _fido2_response_done = |length: u16| {
        global_response_buffer_data_len = length;
        global_response_buffer_done = true;
    };
    let mut _fido2_request_clear = || {
        global_request_buffer_data_len = 0;
        global_request_buffer_done = false;
        global_request_buffer.fill(0u8);
    };
    let mut _fido2_response_clear = || {
        global_response_buffer_data_len = 0;
        global_response_buffer_done = false;
        global_request_buffer.fill(0u8);
    };
    let mut _fido2_request_pending = || -> bool { !global_request_buffer_done };
    let mut _fido2_response_pending = || -> bool { !global_response_buffer_done };
    // event processing
    let _fido2_req = |buff: [u8; 64]| {
        let parser = FIDO2Parser::FIDO2PacketBuilder::new_from_raw_packet(buff);
        match parser {
            Ok(_) => {}
            Err(FIDO2Errors::FIDO2InternalError::CommandNotFoundError) => {
                // let length = _fido2_err_command_not_found()
                //     .apply(&mut global_response_buffer)
                //     .unwrap();
                // _fido2_response_done(length);
            }
            Err(FIDO2Errors::FIDO2InternalError::DataLengthError) => {}
            Err(FIDO2Errors::FIDO2InternalError::ReversedChannelError) => {}
        };
        let req = parser.unwrap();
    };
    // === loop ===
    loop {
        if !hid_usb_dev.poll(&mut [&mut hid_usb_ctrl]) {
            continue;
        }
        let mut buff = [0u8; 64];
        let result = hid_usb_ctrl.pull_raw_output(&mut buff);
        if result.is_ok() {
            let r = result.unwrap();
            let parser = FIDO2Parser::FIDO2PacketBuilder::new_from_raw_packet(buff);
            writeln!(tx, "PC: {:?}", parser).unwrap();
            let parsed = parser.unwrap();
            // response init only
            if parsed.packet_type.is_some()
                && parsed.packet_type.unwrap() != FIDO2Parser::FIDO2PacketCommand::CtapHIDInit
            {
                continue;
            }
            let command_req =
                FIDO2Commands::FIDO2PacketCommandInitRequest::unpack(&parsed.data).unwrap();
            let command_resp = FIDO2Commands::FIDO2PacketCommandInitResponse::new(
                command_req.random,
                [0x00, 0xc0, 0xff, 0xee],
            );
            let mut resp_data = [0u8; 59];
            let data_len = command_resp.apply(&mut resp_data).unwrap();
            let pack = FIDO2Parser::FIDO2PacketBuilder {
                channel_id: 0xffffffff,
                is_seq: false,
                seq_id: 0xff,
                data_length: data_len,
                data: resp_data,
                packet_type: Some(FIDO2Parser::FIDO2PacketCommand::CtapHIDInit),
            };
            let packed = pack.pack().unwrap();
            hid_usb_ctrl.push_raw_input(&packed).unwrap();
        }
    }
}

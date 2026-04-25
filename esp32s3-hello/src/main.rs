#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::main;
use esp_println::println;

esp_bootloader_esp_idf::esp_app_desc!();

#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let _peripherals = esp_hal::init(config);

    let delay = Delay::new();
    let mut tick: u32 = 0;
    loop {
        println!("Hello from ESP32-S3! tick={tick}");
        tick = tick.wrapping_add(1);
        delay.delay_millis(1000);
    }
}

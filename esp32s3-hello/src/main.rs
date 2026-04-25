#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::main;
use esp_println::println;

esp_bootloader_esp_idf::esp_app_desc!();

// graft installs its single trampoline at `graft_entry` (set via
// `GRAFT_ENTRY_SYMBOL=graft_entry` at base build) rather than at
// `main`, so `main` runs base's init/UART setup unconditionally and
// only the handoff into `graft_entry` hits the trampoline. Any output
// from `main` is guaranteed to be base's; the overlay's edited code
// only runs once we're past the trampoline.

#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let _peripherals = esp_hal::init(config);
    println!("graft: post-init, calling graft_entry");
    graft_entry();
}

#[unsafe(no_mangle)]
#[inline(never)]
fn graft_entry() -> ! {
    let delay = Delay::new();
    let mut tick: u32 = 0;
    loop {
        println!("Hello from ESP32-S3! tick={tick}");
        tick = tick.wrapping_add(1);
        delay.delay_millis(1000);
    }
}

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::main;
use esp_println::println;

esp_bootloader_esp_idf::esp_app_desc!();

// M1.n features under test. Each is exercised in `graft_entry` so an
// overlay edit can flip its behavior and we can check the output on
// hardware.

// (1) Mutable static — read/written through unsafe.
static mut TICK_COUNTER: u32 = 0;

// (2) Atomic static — lock-free shared state.
static ATOMIC_TICK: AtomicU32 = AtomicU32::new(0);

// (3) Read-only static — a constant table.
static GREETING_TABLE: [&str; 3] = ["Hello", "Howdy", "Hola"];

// (4) RAM-tagged code (IRAM-resident). `#[link_section = ".rwtext"]`
// places the function in IRAM (loaded from flash to RAM at boot)
// instead of XIP'd from flash. Useful for ISRs that must run with
// flash cache disabled.
#[unsafe(link_section = ".rwtext")]
#[inline(never)]
fn ram_resident_step(prev: u32) -> u32 {
    // Trivial body, but the link_section ensures this lands in `.rwtext`.
    prev.wrapping_add(1)
}

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
    loop {
        let mut_tick = unsafe {
            TICK_COUNTER = TICK_COUNTER.wrapping_add(1);
            TICK_COUNTER
        };
        let atomic_tick = ATOMIC_TICK.fetch_add(1, Ordering::Relaxed) + 1;
        let ram_tick = ram_resident_step(mut_tick);
        let greeting = GREETING_TABLE[0];
        println!(
            "{greeting} from ESP32-S3! mut={mut_tick} atomic={atomic_tick} ram={ram_tick}"
        );
        delay.delay_millis(1000);
    }
}

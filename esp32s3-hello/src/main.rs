#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::main;
use esp_println::println;

esp_bootloader_esp_idf::esp_app_desc!();

// graft slack: zero-cost (in source) reserved flash regions for an
// overlay's `.text` and `.rodata` to land in. Filled with 0xFF so flash
// erase-state and slack-state coincide — overlay-flash writes can skip
// already-erased sectors. The wildcard matchers in esp-hal's linker
// (`*(.rodata .rodata.*)`, `*(.text .literal.*)`) scoop these into the
// existing IROM/DROM output sections, and `rotext_dummy` automatically
// grows `SIZEOF(.rodata)` so `.text` lands past the slack's MMU entries.
//
// The overlay link reads the start vaddr and size of these symbols from
// base.elf and points overlay's `irom_seg` / `drom_seg` at them.
const GRAFT_TEXT_SLACK_LEN: usize = 64 * 1024;
const GRAFT_RODATA_SLACK_LEN: usize = 64 * 1024;

#[repr(C, align(4))]
struct GraftSlack<const N: usize>([u8; N]);

#[unsafe(no_mangle)]
#[used]
#[unsafe(link_section = ".text.graft_slack")]
static GRAFT_TEXT_SLACK: GraftSlack<GRAFT_TEXT_SLACK_LEN> =
    GraftSlack([0xFF; GRAFT_TEXT_SLACK_LEN]);

#[unsafe(no_mangle)]
#[used]
#[unsafe(link_section = ".rodata.graft_slack")]
static GRAFT_RODATA_SLACK: GraftSlack<GRAFT_RODATA_SLACK_LEN> =
    GraftSlack([0xFF; GRAFT_RODATA_SLACK_LEN]);

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

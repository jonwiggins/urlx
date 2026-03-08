#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    // Fuzz URL parsing — must never panic on any input.
    let _ = liburlx::Url::parse(data);
});

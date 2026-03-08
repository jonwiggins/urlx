#![no_main]

use libfuzzer_sys::fuzz_target;
use liburlx::HstsCache;

fuzz_target!(|data: &str| {
    // Fuzz Strict-Transport-Security header parsing — must never panic.
    let mut cache = HstsCache::new();
    cache.store("fuzz.test", data);
    let _ = cache.should_upgrade("fuzz.test");
});

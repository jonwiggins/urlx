#![no_main]

use libfuzzer_sys::fuzz_target;
use liburlx::CookieJar;

fuzz_target!(|data: &str| {
    // Fuzz Set-Cookie parsing — must never panic on any input.
    let mut jar = CookieJar::new();
    jar.store_cookies(&[data], "fuzz.test", "/", true);
    let _ = jar.cookie_header("fuzz.test", "/", false);
});

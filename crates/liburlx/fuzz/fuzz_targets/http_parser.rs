#![no_main]

use libfuzzer_sys::fuzz_target;
use liburlx::protocol::http::h1::parse_response;

fuzz_target!(|data: &[u8]| {
    // Fuzz HTTP/1.1 response parsing — must never panic on any input.
    let _ = parse_response(data, "http://fuzz.test", false);
    let _ = parse_response(data, "http://fuzz.test", true); // HEAD mode
});

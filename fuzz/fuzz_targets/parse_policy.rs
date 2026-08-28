#![no_main]

use libfuzzer_sys::fuzz_target;
use setools_policy_binary::{ParserLimits, parse_policy_header, parse_policy_prefix_with_limits};

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_PEAK_BYTES: usize = 64 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let _ = parse_policy_header(data);
    let limits = ParserLimits {
        max_serialized_prefix_bytes: MAX_INPUT_BYTES,
        max_total_allocation_bytes: MAX_PEAK_BYTES,
        ..ParserLimits::default()
    };
    if let Ok(prefix) = parse_policy_prefix_with_limits(data, limits) {
        let _ = prefix.to_policy("fuzz-input.policy".into());
    }
});

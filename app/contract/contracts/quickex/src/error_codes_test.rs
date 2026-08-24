//! Compatibility coverage for the public numeric error-code contract.

extern crate std;

use std::{fmt::Write, string::String};

const ERROR_CODE_SNAPSHOT: &str = include_str!("error_codes.snapshot");
const ERRORS_SOURCE: &str = include_str!("errors.rs");

#[test]
fn quickex_error_codes_match_snapshot() {
    let enum_body = ERRORS_SOURCE
        .split_once("pub enum QuickexError {")
        .expect("QuickexError declaration must exist")
        .1;

    let mut actual = String::new();
    for line in enum_body.lines() {
        let line = line.trim();
        if line == "}" {
            break;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim().trim_end_matches(',').trim();
        if name.chars().all(|character| character.is_ascii_alphanumeric() || character == '_')
            && value.parse::<u32>().is_ok()
        {
            writeln!(actual, "{name}={value}").expect("writing to a String cannot fail");
        }
    }

    assert_eq!(
        actual, ERROR_CODE_SNAPSHOT,
        "QuickexError codes changed. Existing entries must retain their order and values; \
         new variants may only be appended, with the snapshot updated in the same change."
    );
}

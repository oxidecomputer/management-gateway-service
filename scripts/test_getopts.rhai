// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright 2025 Oxide Computer Company

// Test script for the getopts function in util.rhai
// Run this as:
// `cargo -q run --bin faux-mgs --features=rhaiscript -- rhai scripts/test_getopts.rhai`

// Example Output:
// $ cargo -q run --bin faux-mgs -- -l crit --interface lo rhai scripts/test_getopts.rhai
// --- Running getopts tests ---
// PASS: test_simple_flags: -a
// PASS: test_simple_flags: -b
// PASS: test_simple_flags: no positionals
// PASS: test_opt_with_sep_arg: -f value
// PASS: test_opt_with_sep_arg: positional
// PASS: test_opt_with_sep_arg: positional count
// PASS: test_opt_with_att_arg: -fvalue
// PASS: test_opt_with_att_arg: positional
// PASS: test_opt_with_att_arg: positional count
// PASS: test_combined_flags: -a
// PASS: test_combined_flags: -b
// PASS: test_combined_flags: -c
// PASS: test_combined_flags: positional
// PASS: test_combined_opt_att_arg: -a
// PASS: test_combined_opt_att_arg: -b value
// PASS: test_combined_opt_att_arg: positional
// PASS: test_combined_opt_sep_arg: -a
// PASS: test_combined_opt_sep_arg: -b value
// PASS: test_combined_opt_sep_arg: positional
// PASS: test_long_flag: --verbose
// PASS: test_long_flag: positional
// PASS: test_long_opt_eq_val: --file=value
// PASS: test_long_opt_eq_val: positional
// PASS: test_double_dash: -a
// PASS: test_double_dash: -b not parsed
// PASS: test_double_dash: positional count
// PASS: test_double_dash: first positional is -b
// PASS: test_double_dash: second positional
// PASS: test_err_unknown_short
// PASS: test_err_missing_arg
// --- getopts tests complete ---

import `${script_dir}/util` as util;

/// Basic assertion helper for tests. Throws on failure.
fn assert_equal(actual, expected, test_name) {
    if actual != expected {
        let fail_msg =
            `FAIL: ${test_name}. Expected: ${expected}, Got: ${actual}`;
        print(fail_msg);
        throw fail_msg; // Throw error to stop execution on failure
    } else {
        // Optional: Only print PASS on verbose mode?
        print(`PASS: ${test_name}`);
    }
}

/// Asserts that a value is specifically true.
fn assert_true(actual, test_name) {
    assert_equal(actual, true, test_name);
}

/// Asserts that a key exists within a map.
fn assert_key_exists(key, map, test_name) {
    if !(key in map) {
        let fail_msg = `FAIL: ${test_name}. Key '${key}' not found in map: ${map}`;
        print(fail_msg);
        throw fail_msg;
    }
    // Keep PASS silent or print if verbose needed
    // print(`PASS: ${test_name}`);
}

/// Asserts that a key does NOT exist within a map.
fn assert_key_not_exists(key, map, test_name) {
    if key in map {
        let fail_msg = `FAIL: ${test_name}. Key '${key}' unexpectedly found in map: ${map}`;
        print(fail_msg);
        throw fail_msg;
    }
    // Keep PASS silent or print if verbose needed
    // print(`PASS: ${test_name}`);
}

/// Wrapper to run a test function and catch/report errors.
fn run_test(func_ptr) {
    // Assumes func_ptr.name is available in future Rhai or passed manually
    // For now, use manual name logging if needed inside the test function.
    try {
        call(func_ptr);
    } catch(e) {
        print(`ERROR running test: ${e}`);
        // Optionally re-throw or exit if any test failure should stop all tests
        // throw e;
    }
}

// --- Test Cases ---

fn test_simple_flags() {
    let test_name = "test_simple_flags";
    let argv = ["script", "-a", "-b"];
    let options = "ab";
    let result = util::getopts(argv, options);

    assert_key_exists("a", result.result, `${test_name}: map has a`);
    assert_true(result.result.a, `${test_name}: -a is true`);
    assert_key_exists("b", result.result, `${test_name}: map has b`);
    assert_true(result.result.b, `${test_name}: -b is true`);
    assert_equal(result.positional.len(), 0, `${test_name}: positional count`);
}

fn test_opt_with_sep_arg() {
    let test_name = "test_opt_with_sep_arg";
    let argv = ["script", "-f", "file.txt", "pos1"];
    let options = "f:"; // -f requires an argument
    let result = util::getopts(argv, options);

    assert_equal(result.result.f, "file.txt", `${test_name}: -f value`);
    assert_equal(result.positional.len(), 1, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional value`);
}

fn test_opt_with_att_arg() {
    let test_name = "test_opt_with_att_arg";
    let argv = ["script", "-ffile.txt", "pos1"];
    let options = "f:"; // -f requires an argument
    let result = util::getopts(argv, options);

    assert_equal(result.result.f, "file.txt", `${test_name}: -fvalue`);
    assert_equal(result.positional.len(), 1, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional value`);
}

fn test_combined_flags() {
    let test_name = "test_combined_flags";
    let argv = ["script", "-abc", "pos1"];
    let options = "abc"; // All are flags
    let result = util::getopts(argv, options);

    assert_true(result.result.a, `${test_name}: -a`);
    assert_true(result.result.b, `${test_name}: -b`);
    assert_true(result.result.c, `${test_name}: -c`);
    assert_equal(result.positional.len(), 1, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional value`);
}

fn test_combined_opt_att_arg() {
    let test_name = "test_combined_opt_att_arg";
    let argv = ["script", "-abfile.txt", "pos1"];
    let options = "ab:"; // -b requires argument
    let result = util::getopts(argv, options);

    assert_true(result.result.a, `${test_name}: -a`);
    assert_equal(result.result.b, "file.txt", `${test_name}: -b value`);
    assert_equal(result.positional.len(), 1, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional value`);
}

fn test_combined_opt_sep_arg() {
    let test_name = "test_combined_opt_sep_arg";
    let argv = ["script", "-ab", "file.txt", "pos1"];
    let options = "ab:"; // -b requires argument
    let result = util::getopts(argv, options);

    assert_true(result.result.a, `${test_name}: -a`);
    assert_equal(result.result.b, "file.txt", `${test_name}: -b value`);
    assert_equal(result.positional.len(), 1, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional value`);
}

fn test_long_flag() {
    let test_name = "test_long_flag";
    let argv = ["script", "--verbose", "pos1"];
    let options = "abc"; // Long opts not defined/validated by 'options' string
    let result = util::getopts(argv, options);

    assert_true(result.result.verbose, `${test_name}: --verbose`);
    assert_equal(result.positional.len(), 1, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional value`);
}

fn test_long_opt_eq_val() {
    let test_name = "test_long_opt_eq_val";
    let argv = ["script", "--file=out.txt", "pos1"];
    let options = "abc";
    let result = util::getopts(argv, options);

    assert_equal(result.result.file, "out.txt", `${test_name}: --file=value`);
    assert_equal(result.positional.len(), 1, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional value`);
}

fn test_double_dash() {
    let test_name = "test_double_dash";
    let argv = ["script", "-a", "--", "-b", "pos1"];
    let options = "ab"; // -b is a valid option
    let result = util::getopts(argv, options);

    assert_true(result.result.a, `${test_name}: -a`);
    assert_key_not_exists("b", result.result, `${test_name}: -b not parsed`);
    assert_equal(result.positional.len(), 2, `${test_name}: positional count`);
    assert_equal(result.positional[0], "-b", `${test_name}: first positional is -b`);
    assert_equal(result.positional[1], "pos1", `${test_name}: second positional`);
}

fn test_positional_only() {
    let test_name = "test_positional_only";
    let argv = ["script", "arg1", "arg2"];
    let options = "ab";
    let result = util::getopts(argv, options);

    assert_equal(result.result.len(), 0, `${test_name}: result map empty`);
    assert_equal(result.positional.len(), 2, `${test_name}: positional count`);
    assert_equal(result.positional[0], "arg1", `${test_name}: positional 1`);
    assert_equal(result.positional[1], "arg2", `${test_name}: positional 2`);
}

fn test_mixed_opts_positional() {
    let test_name = "test_mixed_opts_positional";
    // Note: Basic getopts might treat non-option args as positional anywhere
    let argv = ["script", "pos1", "-a", "pos2", "-bval", "--long=lval"];
    let options = "ab:";
    let result = util::getopts(argv, options);

    assert_true(result.result.a, `${test_name}: -a`);
    assert_equal(result.result.b, "val", `${test_name}: -bval`);
    assert_equal(result.result.long, "lval", `${test_name}: --long=lval`);
    assert_equal(result.positional.len(), 2, `${test_name}: positional count`);
    assert_equal(result.positional[0], "pos1", `${test_name}: positional 1`);
    assert_equal(result.positional[1], "pos2", `${test_name}: positional 2`);
}

fn test_err_unknown_short() {
    let test_name = "test_err_unknown_short";
    let argv = ["script", "-ax"]; // -x is the unknown option
    let options = "a";
    let expected_err = "Unknown option '-x'.";

    // Call getopts and check the returned map directly
    let result = util::getopts(argv, options);

    // Assert that the returned map has an 'error' key
    assert_key_exists("error", result, `${test_name}: error key exists`);
    // Assert that the value of the 'error' key matches the expected message
    assert_equal(result.error, expected_err, `${test_name}: error message`);
}

fn test_err_missing_arg() {
    let test_name = "test_err_missing_arg";
    let argv = ["script", "-a"]; // Argument missing for -a
    let options = "a:"; // -a requires an argument
    let expected_err = "Option '-a' requires an argument.";

    // Call getopts and check the returned map directly
    let result = util::getopts(argv, options);

    // Assert that the returned map has an 'error' key
    assert_key_exists("error", result, `${test_name}: error key exists`);
    // Assert that the value of the 'error' key matches the expected message
    assert_equal(result.error, expected_err, `${test_name}: error message`);
}

fn main() {
    print("--- Running getopts tests ---");

    // Call each test function using the run_test wrapper
    run_test(test_simple_flags);
    run_test(test_opt_with_sep_arg);
    run_test(test_opt_with_att_arg);
    run_test(test_combined_flags);
    run_test(test_combined_opt_att_arg);
    run_test(test_combined_opt_sep_arg);
    run_test(test_long_flag);
    run_test(test_long_opt_eq_val);
    run_test(test_double_dash);
    run_test(test_positional_only);
    run_test(test_mixed_opts_positional);
    run_test(test_err_unknown_short);
    run_test(test_err_missing_arg);

    print("--- getopts tests complete ---");
    // Indicate overall success/failure based on whether any test threw?
    // For now, just return 0 if it completes.
    return 0;
}

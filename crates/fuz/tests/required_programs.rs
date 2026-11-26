//! The programs this crate's tests run. The FIFO tests (`self_cli`'s
//! `self_bootstrap_leaves_a_fifo_rc_untouched`, `bootstrap`'s
//! `update_rc_file_leaves_a_fifo_untouched`) make their FIFO with `mkfifo(1)`
//! — std has no constructor for one — and check nothing where it is absent,
//! so `cargo test` runs on a machine without it — and this test fails there,
//! so a run that skipped those tests can't pass unnoticed.
//! `FUZ_TEST_ALLOW_NO_MKFIFO=1` accepts its absence.

mod common;

#[test]
fn the_mkfifo_the_fifo_tests_run_is_installed() {
    let dir = common::fresh_home();
    let found = common::make_fifo(&dir.path().join("fifo"));
    let allowed = std::env::var_os("FUZ_TEST_ALLOW_NO_MKFIFO").is_some_and(|value| value == "1");
    assert!(
        found || allowed,
        "`mkfifo` can't make a FIFO here, so the FIFO tests checked nothing — install it \
         (or set FUZ_TEST_ALLOW_NO_MKFIFO=1)"
    );
}

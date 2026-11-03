//! Windows only: does every name `SafeName` accepts stay an ordinary file?
//!
//! `docs/SECURITY.md` §5 compares reserved stems ignoring ASCII case only. This
//! asks Windows directly whether names that differ from a device name by one
//! non-ASCII character are still treated as that device, and checks that
//! `SafeName` never returns a name Windows treats as a device.
//!
//! Two probes are used.
//!
//! - `std::path::absolute`, which is `GetFullPathNameW` on Windows. Win32 path
//!   parsing turns `C:\dir\CON` into `\\.\CON`, so a result outside the
//!   directory means Windows saw a device. It reads no file, so every BMP code
//!   point can be tried in every position of every reserved name.
//! - Exclusive creation in a fresh directory, followed by a listing. A name is an
//!   ordinary file only if it was created, is listed under exactly that name, and
//!   is a file. This covers `CONIN$` and `CONOUT$`, which `CreateFileW` handles
//!   itself, and which the path parser may not report.
//!
//! Each reserved name is tried in upper and lower case, with every BMP code
//! point in each position and appended. Matching works on UTF-16 code units, so
//! a character outside the BMP changes the length and cannot match, and one
//! substitution at a time is enough because matching is per character.
//!
//! Observed on Server 2022 (build 20348) and Server 2025 (build 26100): the
//! only non-ASCII devices are `COM` and `LPT` followed by `¹`, `²` or `³`, and
//! `conın$` is an ordinary file. Server 2022 reserves every name in every
//! directory. Server 2025 reserves only `NUL` inside a directory, but every
//! name when bare. See `docs/M2_REPORT.md`.
//!
//! Observations are printed. Run with `-- --nocapture` to see them.

#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use xdcc_core::policy::SafeName;

const BASES: [&str; 8] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "LPT1", "CONIN$", "CONOUT$",
];

/// Each reserved name in upper and lower case, so a non-ASCII character is
/// tried among both, as in `conın$`.
fn bases() -> Vec<String> {
    BASES
        .iter()
        .flat_map(|base| [(*base).to_owned(), base.to_ascii_lowercase()])
        .collect()
}

/// A fresh, empty directory for this run.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("xdcc-device-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// True if Win32 path parsing maps `dir\name` to something outside `dir`.
fn parser_sees_device(dir: &Path, name: &str) -> bool {
    match std::path::absolute(dir.join(name)) {
        Ok(full) => !full.starts_with(dir),
        Err(_) => true,
    }
}

/// True if Win32 path parsing maps the bare relative `name` outside the current
/// directory. Server 2025 (build 26100) keeps more device names for bare names
/// than for names inside a directory.
fn parser_sees_bare_device(cwd: &Path, name: &str) -> bool {
    match std::path::absolute(name) {
        Ok(full) => !full.starts_with(cwd),
        Err(_) => true,
    }
}

/// True if `name` can be created in `dir` as an ordinary file of that name.
fn creates_ordinary_file(dir: &Path, name: &str) -> Result<(), String> {
    let path = dir.join(name);
    let opened = OpenOptions::new().write(true).create_new(true).open(&path);
    if let Err(error) = &opened {
        return Err(format!("open failed: {error}"));
    }
    drop(opened);
    let listed: Vec<OsString> = fs::read_dir(dir)
        .map_err(|error| format!("listing failed: {error}"))?
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .collect();
    let found = listed.iter().any(|entry| entry == name);
    let is_file = fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file());
    for entry in &listed {
        let _ = fs::remove_file(dir.join(entry));
    }
    if found && is_file {
        Ok(())
    } else {
        Err(format!(
            "not an ordinary file (listed {found}, file {is_file}, saw {listed:?})"
        ))
    }
}

/// Every BMP scalar outside ASCII.
fn bmp_non_ascii() -> impl Iterator<Item = char> {
    (0x80u32..=0xFFFF).filter_map(char::from_u32)
}

fn substitute(base: &str, at: usize, with: char) -> String {
    base.chars()
        .enumerate()
        .map(|(index, c)| if index == at { with } else { c })
        .collect()
}

fn codepoints(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_graphic() {
                c.to_string()
            } else {
                format!("U+{:04X}", u32::from(c))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Non-ASCII characters whose Unicode case mappings reach `ascii`, plus its
/// full-width form. These are the likeliest to fold onto the ASCII letter.
fn case_variants(ascii: char) -> Vec<char> {
    let mut out: Vec<char> = bmp_non_ascii()
        .filter(|c| {
            let upper: String = c.to_uppercase().collect();
            let lower: String = c.to_lowercase().collect();
            let target = ascii.to_string();
            upper.eq_ignore_ascii_case(&target)
                || lower.eq_ignore_ascii_case(&target)
                || upper
                    .chars()
                    .next()
                    .is_some_and(|u| u.eq_ignore_ascii_case(&ascii))
                || lower
                    .chars()
                    .next()
                    .is_some_and(|l| l.eq_ignore_ascii_case(&ascii))
        })
        .collect();
    if ascii.is_ascii_graphic() {
        if let Some(wide) = char::from_u32(u32::from(ascii) - 0x21 + 0xFF01) {
            out.push(wide);
        }
    }
    out
}

#[test]
fn the_probes_see_ascii_device_names() {
    // Without this, a probe that never detects anything would pass vacuously.
    // Only what holds on every supported version is required. Server 2025
    // treats `CON` and `NUL.txt` inside a directory as files, but `NUL` there,
    // and every bare name, is still a device.
    let dir = scratch("control");
    let cwd = std::env::current_dir().unwrap();
    for name in ["NUL", "nul"] {
        assert!(parser_sees_device(&dir, name), "{name} in a directory");
    }
    for name in ["CON", "con", "NUL", "COM1", "lpt1", "AUX", "prn"] {
        assert!(parser_sees_bare_device(&cwd, name), "bare {name}");
    }
    for name in BASES.iter().copied().chain(["NUL.txt", "CON.txt"]) {
        println!(
            "control: {name}: in a directory {}, bare {}, created {:?}",
            parser_sees_device(&dir, name),
            parser_sees_bare_device(&cwd, name),
            creates_ordinary_file(&dir, name).is_ok(),
        );
    }
    assert!(!parser_sees_device(&dir, "CONX"));
    assert!(!parser_sees_bare_device(&cwd, "CONX"));
    assert!(creates_ordinary_file(&dir, "plain.txt").is_ok());
    assert!(creates_ordinary_file(&dir, "NUL").is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn no_accepted_name_is_a_device_to_the_path_parser() {
    let dir = scratch("parser");
    let cwd = std::env::current_dir().unwrap();
    let sees = |name: &str| parser_sees_device(&dir, name) || parser_sees_bare_device(&cwd, name);
    let mut devices = BTreeSet::new();
    for base in bases() {
        let base = base.as_str();
        for c in bmp_non_ascii() {
            // Each position replaced by `c`, and `c` appended.
            for at in 0..base.chars().count() {
                let name = substitute(base, at, c);
                if sees(&name) {
                    devices.insert(name);
                }
            }
            let name = format!("{base}{c}");
            if sees(&name) {
                devices.insert(name);
            }
        }
    }
    println!(
        "path parser: {} non-ASCII variants are devices",
        devices.len()
    );
    let mut failures = Vec::new();
    for name in &devices {
        let result = SafeName::from_bytes(name.as_bytes());
        println!(
            "  DEVICE {} -> SafeName {:?}",
            codepoints(name),
            result.as_ref().map(SafeName::as_str)
        );
        if let Ok(safe) = result {
            if sees(safe.as_str()) {
                failures.push(codepoints(name));
            }
        }
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(
        failures.is_empty(),
        "SafeName returned devices for {failures:?}"
    );
}

#[test]
fn no_accepted_name_is_a_device_when_created() {
    let dir = scratch("create");
    let mut names = BTreeSet::new();
    for base in bases() {
        names.insert(base.clone());
        for (at, letter) in base.chars().enumerate() {
            for c in case_variants(letter) {
                names.insert(substitute(&base, at, c));
            }
        }
    }
    for digit in [
        '\u{B9}', '\u{B2}', '\u{B3}', '\u{2074}', '\u{2081}', '\u{FF11}', '\u{0661}', '\u{0967}',
    ] {
        names.insert(format!("COM{digit}"));
        names.insert(format!("LPT{digit}"));
    }
    let mut failures = Vec::new();
    for name in &names {
        let raw = creates_ordinary_file(&dir, name);
        let safe = SafeName::from_bytes(name.as_bytes());
        let safe_result = safe
            .as_ref()
            .map(|safe| creates_ordinary_file(&dir, safe.as_str()));
        println!(
            "  {:<40} raw: {:<60} SafeName: {:?} {:?}",
            codepoints(name),
            match &raw {
                Ok(()) => "ordinary file".to_owned(),
                Err(why) => why.clone(),
            },
            safe.as_ref().map(SafeName::as_str),
            safe_result,
        );
        if let Ok(Err(why)) = safe_result {
            failures.push(format!("{} -> {why}", codepoints(name)));
        }
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(
        failures.is_empty(),
        "SafeName returned non-ordinary files: {failures:#?}"
    );
}

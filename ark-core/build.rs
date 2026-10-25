// SPDX-License-Identifier: GPL-3.0-only

use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ort_rc_10)");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let lockfile = Path::new(&manifest_dir).join("../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let Ok(lockfile) = fs::read_to_string(lockfile) else {
        return;
    };

    let mut in_ort_package = false;
    for line in lockfile.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            in_ort_package = false;
            continue;
        }
        if trimmed == "name = \"ort\"" {
            in_ort_package = true;
            continue;
        }
        if in_ort_package && trimmed == "version = \"2.0.0-rc.10\"" {
            println!("cargo:rustc-cfg=ort_rc_10");
            return;
        }
    }
}

//! Op-path sleep guard (Stop design v5 §5.8): "Ban `std::thread::sleep` on op
//! paths: unlock `src/{aacs,css,ld}` ... Use `Halt::wait` / `pause` instead."
//!
//! Every production (non-`#[cfg(test)]`) line under `src/aacs`, `src/css` and
//! `src/ld` is scanned for the substring `thread::sleep(` (catching both
//! `std::thread::sleep(` and an already-imported `thread::sleep(`). A raw sleep
//! on these op paths can't be cancelled; [`ScsiTransport::pause`] (which a
//! cancellable host wires to `Halt::wait`) is the sanctioned replacement.
//! `clippy.toml`'s `disallowed-methods` can't scope to a subdirectory, hence
//! this grep test instead of a lint config entry.

use std::path::{Path, PathBuf};

/// The banned substring: matches `std::thread::sleep(` and `thread::sleep(`.
const BANNED: &str = "thread::sleep(";

/// Every `.rs` file under `dir`, recursively.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// 1-based line numbers of every `thread::sleep(` call in `src` that is NOT
/// inside a `#[cfg(test)]` item or block. Tracks brace depth: a `#[cfg(test)]`
/// attribute starts a "pending" item; if that item opens a `{`, everything
/// until the matching `}` is skipped; if it's a single-line item ending in
/// `,`/`;` with no `{` (e.g. a struct field), only that line is skipped.
fn op_path_hits(src: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut depth: i32 = 0;
    let mut paren_depth: i32 = 0;
    let mut pending_cfg_test = false;
    let mut skip_until_depth: Option<i32> = None;

    for (idx, line) in src.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim();
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;

        if let Some(d) = skip_until_depth {
            depth += opens - closes;
            if depth <= d {
                skip_until_depth = None;
            }
            continue;
        }

        if trimmed.starts_with("#[cfg(test)]") {
            pending_cfg_test = true;
            continue;
        }

        if pending_cfg_test {
            paren_depth += line.matches('(').count() as i32 - line.matches(')').count() as i32;
            if opens > 0 {
                let before = depth;
                depth += opens - closes;
                skip_until_depth = Some(before);
            } else if paren_depth <= 0 && (trimmed.ends_with(',') || trimmed.ends_with(';')) {
                pending_cfg_test = false;
            }
            // Multi-line signature before `{` (or an open param list): stay
            // pending, keep scanning.
            continue;
        }

        depth += opens - closes;
        if line.contains(BANNED) {
            hits.push(lineno);
        }
    }
    hits
}

/// Guard: no raw `thread::sleep(` in production code under `src/aacs`,
/// `src/css` or `src/ld` (Stop design v5 §5.8). Use `pause` / `Halt::wait`.
#[test]
fn no_raw_sleep_on_unlock_op_paths() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for sub in ["src/aacs", "src/css", "src/ld"] {
        rs_files(&root.join(sub), &mut files);
    }
    assert!(
        files.len() >= 3,
        "the scan must reach real files (found {})",
        files.len()
    );

    let mut hits = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).expect("read source");
        for line in op_path_hits(&src) {
            hits.push(format!(
                "{}:{line}",
                f.strip_prefix(root).unwrap().display()
            ));
        }
    }
    assert!(
        hits.is_empty(),
        "raw thread::sleep on an unlock op path (use pause / Halt::wait instead):\n{}",
        hits.join("\n")
    );
}

/// Self-test: the guard skips `#[cfg(test)]` items/blocks and catches a
/// production-code sleep.
#[test]
fn the_guard_skips_cfg_test_and_catches_production_sleeps() {
    let clean = [
        // A `mod tests { ... }` block, sleep inside it ignored.
        "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn g() {\n        std::thread::sleep(D);\n    }\n}\n",
        // A single test-only fn (one-liner body).
        "#[cfg(test)]\nfn helper() { std::thread::sleep(D); }\n",
        // A cfg(test)-gated struct field (single line, ends in `,`).
        "struct S {\n    #[cfg(test)]\n    x: Option<u8>,\n}\n",
        // A cfg(test)-gated statement inside a normal (production) fn.
        "fn real() -> X {\n    #[cfg(test)]\n    if let Some(m) = HOOK.get() {\n        thread::sleep(D);\n        return m();\n    }\n    Y\n}\n",
        // A multi-line test-only fn signature before the brace.
        "#[cfg(test)]\nfn helper(\n    a: u8,\n) -> Bar {\n    thread::sleep(D);\n    Bar\n}\n",
    ];
    for s in &clean {
        assert!(op_path_hits(s).is_empty(), "false positive: {s}");
    }

    let dirty = [
        "fn real() {\n    std::thread::sleep(D);\n}\n",
        "fn real() {\n    thread::sleep(D);\n}\n",
    ];
    for s in &dirty {
        assert_eq!(op_path_hits(s), vec![2], "missed hit: {s}");
    }
}

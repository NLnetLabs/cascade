// Note to developers extending/debugging this file: When this file throws
// errors or warnings, `cargo -vv build` does not show the output of the
// `println!`s of this file. Resolve all warning first, trigger a re-build
// (e.g. `touch build.rs`), and run `cargo -vv build` again.

#![allow(clippy::disallowed_macros, reason = "we're not printing in color")]

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, Output};

fn strip_newline(s: String) -> String {
    s.strip_suffix("\n").unwrap_or(&s).into()
}

fn run_cmd<I, S>(cmd: &str, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(cmd).args(args).output().unwrap()
}

fn run_cmd_strip<I, S>(cmd: &str, args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let out = Command::new(cmd).args(args).output().unwrap();
    strip_newline(String::from_utf8(out.stdout).unwrap())
}

fn main() {
    // Rust build scripts are per package, therefore this script is both run
    // from the project's root directory and the crates sub-directory.
    let package = env!("CARGO_PKG_NAME");
    let is_jj = match package {
        "cascaded" => PathBuf::from(".jj").exists(),
        "cascade" => PathBuf::from("../../.jj").exists(),
        // This build script is only run for the packages `cascade` and
        // `cascaded`. If we link the build.rs file to other packages too, we
        // need to add them to the match arm above.
        _ => unreachable!(),
    };

    let git_root = if is_jj {
        run_cmd_strip("jj", ["workspace", "root", "--ignore-working-copy"])
    } else {
        let is_in_git_worktree = run_cmd("git", ["rev-parse", "--is-inside-work-tree"])
            .status
            .success();
        if is_in_git_worktree {
            run_cmd_strip("git", ["rev-parse", "--show-toplevel"])
        } else {
            match package {
                "cascaded" => println!("cargo::rerun-if-changed=.git"),
                "cascade" => println!("cargo::rerun-if-changed=../../.git"),
                _ => {}
            }
            print_version(concat!(env!("CARGO_PKG_VERSION"), " at ", "no-git"));
            return;
        }
    };

    // Generate rerun-if statements to tell Cargo to run this script again
    // when relevant files change (including relevant git files to catch
    // commits, etc.).
    // If a file does not exist, cargo will always rerun the build script.
    generate_project_rerun_with_prefix(
        &git_root,
        vec![
            "Cargo.lock",
            "Cargo.toml",
            "build.rs",
            "crates/",
            "etc/",
            "src/",
        ],
    );

    // Monitor files related to commit changes
    if is_jj {
        generate_project_rerun_with_prefix(&git_root, vec![".jj/working_copy/checkout"]);
    } else {
        let git_head_ref_cmd = run_cmd("git", ["symbolic-ref", "HEAD"]);
        let git_dir = run_cmd_strip("git", ["rev-parse", "--git-dir"]);

        generate_project_rerun_with_prefix(&git_dir, vec!["HEAD"]);

        if git_head_ref_cmd.status.success() {
            let git_head_ref = strip_newline(String::from_utf8(git_head_ref_cmd.stdout).unwrap());
            let git_common_dir = run_cmd_strip("git", ["rev-parse", "--git-common-dir"]);
            generate_project_rerun_with_prefix(&git_common_dir, vec![&git_head_ref]);
        } else {
            // .git/HEAD is likely a detached HEAD right now (aka contains
            // a commit hash). Once that changes, the build script will be
            // re-run and the above branch will be triggered.
        }
    }

    let version = generate_version_string(is_jj);
    print_version(&version);
}

fn generate_version_string(is_jj: bool) -> String {
    let (mut git_hash, is_dirty) = if is_jj {
        let git_hash = run_cmd_strip(
            "jj",
            [
                "log",
                "--ignore-working-copy",
                "-G",
                "-T",
                "'commit_id'",
                "-r",
                "@-",
            ],
        );
        let is_dirty = match run_cmd_strip("jj", ["log", "-G", "-T", "empty"]).as_str() {
            "true" => false,
            "false" => true,
            _ => unreachable!(),
        };
        (git_hash, is_dirty)
    } else {
        let git_hash = run_cmd_strip("git", ["rev-parse", "--short", "HEAD"]);
        let is_dirty = !run_cmd("git", ["diff-index", "--quiet", "HEAD"])
            .status
            .success();
        (git_hash, is_dirty)
    };

    if is_dirty {
        git_hash.push('-');
        git_hash.push_str("dirty");
    }

    format!("{} at {}", env!("CARGO_PKG_VERSION"), git_hash)
}

fn print_version(s: &str) {
    println!("cargo::rustc-env=CASCADE_BUILD_VERSION={s}");
}

fn generate_project_rerun_with_prefix(prefix: &str, paths: Vec<&str>) {
    for path in paths {
        let mut p = PathBuf::from(prefix);
        p.push(path);
        if p.exists() {
            // https://doc.rust-lang.org/cargo/reference/build-scripts.html#change-detection
            println!("cargo::rerun-if-changed={prefix}/{path}");
        } else {
            println!(
                "cargo::warning=File {path} does not exist but was expected for the rerun check"
            );
        }
    }
}

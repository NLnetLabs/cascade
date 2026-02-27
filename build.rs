//! This build script generates the version string for cascade and cascaded.
//!
//! It tries to determine which git commit is used to build the binary
//! currently being built, and adds that commit hash to the version string for
//! reference in issues. This can be disabled with the
//! CASCADE_SKIP_VERSION_COMMIT environment variable set to 1 or true.
//!
//! As some of our developers use jj as a wrapper around git, the usual
//! assumptions that the repository always contains a .git file or directory,
//! does not hold. Therefore, we check for the .jj directory and use the jj
//! tool if that directory exists. Otherwise we use the normal git approach.
//!
//! By default, Cargo will re-run the build script if any of the files in the
//! package change. However, we also need to re-run the build script when the
//! git state changes. For example, when someone built the package in a dirty
//! worktree to test their changes (which results in the version string to
//! include <commit>-dirty) and then commits the changes to git, no files in
//! the package have changed but the version string needs to be updated to the
//! freshly created commit. Therefore, we instruct Cargo with the rerun-if
//! statements to re-run the build script when any of the files tracking
//! commit state have changed. However, as using rerun-if disables the
//! default behaviour, we also need to generate the rerun-if statements for
//! the relevant source files of the package [1], [2].
//!
//! [1]: https://doc.rust-lang.org/cargo/reference/build-scripts.html#change-detection
//! [2]: https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed

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

fn run_cmd<I, S>(cmd: &str, args: I) -> Result<Output, std::io::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(cmd).args(args).output()
}

fn run_cmd_strip<I, S>(cmd: &str, args: I) -> Result<String, std::io::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| strip_newline(String::from_utf8(o.stdout).unwrap()))
}

fn main() -> Result<(), ()> {
    // Allow disabling including the git commit, e.g. for release builds.
    if matches!(
        option_env!("CASCADE_SKIP_VERSION_COMMIT"),
        Some("true" | "1")
    ) {
        print_version(env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Rust build scripts are per package, therefore this script is both run
    // from the project's root directory and the crates sub-directory.
    let package = env!("CARGO_PKG_NAME");
    // Check whether this repository is managed by jj or not.
    let is_jj = match package {
        "cascaded" => PathBuf::from(".jj").exists(),
        "cascade" => PathBuf::from("../../.jj").exists(),
        // This build script is only run for the packages `cascade` and
        // `cascaded`. If we link the build.rs file to other packages too, we
        // need to add them to the match arm above.
        _ => unreachable!(),
    };

    // Determine the repository's root directory, if it is in a repository and
    // not just a directory from a downloaded tar-ball of a release.
    let git_root = if is_jj {
        // While the existance of a .jj directory doesn't necessarily mean
        // that we cannot fall-back to using git, we won't fall-back to git to
        // avoid potential false commit hashes. A jj worktree located inside
        // an existing git repository does not contain a .git file or
        // directory. Therefore, git will act on the git repository containing
        // the worktre and report wrong status and checked out commits.

        // On first run of jj, check if it executes ok (aka do not unwrap, but catch the error)
        run_cmd_strip("jj", ["workspace", "root", "--ignore-working-copy"]).map_err(|e| {
            let msg = match e.kind() {
                std::io::ErrorKind::NotFound => "jj it not installed",
                std::io::ErrorKind::PermissionDenied => "jj is not executable",
                _ => "there was an unknown error while attempting to run jj",
            };
            println!(
                "cargo::warning=A .jj directory exists, but {msg}. Unable to determine git revision..."
            );

            // jj failed, so we instruct Cargo to re-run the build script when
            // the jj state changes.
            match package {
                "cascaded" => println!("cargo::rerun-if-changed=.jj"),
                "cascade" => println!("cargo::rerun-if-changed=../../.jj"),
                _ => {}
            }
        }).ok()
    } else {
        // On first run of git, check if it executes ok (aka do not unwrap, but catch the error)
        let is_in_git_worktree = run_cmd("git", ["rev-parse", "--is-inside-work-tree"])
            .map_err(|e| {
                let msg = match e.kind() {
                    std::io::ErrorKind::NotFound => "git is not installed",
                    std::io::ErrorKind::PermissionDenied => "git is not executable",
                    _ => "unknown error occured while attempting to run git",
                };
                println!("cargo::warning={msg}. Unable to determine git revision...");

                // git failed to execute, instruct Cargo to re-run the build
                // script when the git state changes.
                match package {
                    "cascaded" => println!("cargo::rerun-if-changed=.git"),
                    "cascade" => println!("cargo::rerun-if-changed=../../.git"),
                    _ => {}
                }
            })
            .ok()
            .map(|o| o.status.success());
        if let Some(is_in_git_worktree) = is_in_git_worktree
            && is_in_git_worktree
        {
            Some(run_cmd_strip("git", ["rev-parse", "--show-toplevel"]).unwrap())
        } else {
            None
        }
    };

    if let Some(git_root) = git_root {
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
            // Check which branch HEAD points to (if any).
            let git_head_ref_cmd = run_cmd("git", ["symbolic-ref", "HEAD"]).unwrap();
            let git_dir = run_cmd_strip("git", ["rev-parse", "--git-dir"]).unwrap();

            generate_project_rerun_with_prefix(&git_dir, vec!["HEAD"]);

            if git_head_ref_cmd.status.success() {
                let git_head_ref =
                    strip_newline(String::from_utf8(git_head_ref_cmd.stdout).unwrap());
                let git_common_dir =
                    run_cmd_strip("git", ["rev-parse", "--git-common-dir"]).unwrap();
                // Monitor the branch's "HEAD", which contains the current commit
                generate_project_rerun_with_prefix(&git_common_dir, vec![&git_head_ref]);
            } else {
                // .git/HEAD is likely a detached HEAD right now (aka contains
                // a commit hash). Once that changes, the build script will be
                // re-run and the above branch will be triggered.
            }
        }

        let version = generate_version_string(is_jj);
        print_version(&version);
        Ok(())
    } else {
        print_version(concat!(env!("CARGO_PKG_VERSION"), " (no-git)"));
        Ok(())
    }
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
                "commit_id.short(10)",
                "-r",
                "@-",
            ],
        )
        .unwrap();
        let is_dirty = match run_cmd_strip("jj", ["log", "-G", "-T", "empty", "-r", "@"])
            .unwrap()
            .as_str()
        {
            "true" => false,
            "false" => true,
            _ => unreachable!(),
        };
        (git_hash, is_dirty)
    } else {
        let git_hash = run_cmd_strip("git", ["rev-parse", "--short=10", "HEAD"]).unwrap();
        let is_dirty = !run_cmd("git", ["diff-index", "--quiet", "HEAD"])
            .unwrap()
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

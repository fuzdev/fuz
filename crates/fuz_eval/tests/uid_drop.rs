//! The uid drop, run as root: a root eval runs `fgro` as the project's owner —
//! the user `sudo` names when that user owns it — with no supplementary groups,
//! still exec'd through the held descriptor (`/proc/self/fd/<n>`) once the child
//! is that user, from a directory that user can't search.
//!
//! Marked `#[ignore]`, and every case fails rather than passes untested when the
//! process isn't in the mode it names. Build the suite as yourself, then run the
//! built binary as root, once per mode, without Cargo:
//!
//! ```text
//! cargo test -p fuz_eval --test uid_drop --no-run   # prints the binary's path
//! sudo env FUZ_EVAL_TEST_FGRO=/abs/path/to/fgro FUZ_EVAL_TEST_WRITE_HOME=1 \
//!     <binary> --ignored sudo_drop_
//! sudo env -u SUDO_UID -u SUDO_GID <binary> --ignored owner_drop_
//! ```
//!
//! The first runs under `sudo`'s `SUDO_UID` and `SUDO_GID`; the second clears
//! them, so the drop is to the project's owner, which the suite makes the owner
//! of Cargo's target scratch directory. Each mode's cases share its prefix, and
//! neither prefix matches the other's cases.
//!
//! The home case writes `package.json` and `.fuz_eval_uid_drop_<pid>.ts` into the
//! `sudo` user's home for its duration, so it runs only with
//! `FUZ_EVAL_TEST_WRITE_HOME=1` (without it, it prints a note and passes), and
//! refuses to run when a `package.json` is already there. A run killed before
//! its cleanup leaves both: delete `~/package.json` and
//! `~/.fuz_eval_uid_drop_*.ts`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fuz_eval::{
    EvalError, EvalOutput, EvalRequest, FgroPin, RunAsProblem, eval_module, fgro_blake3,
};

use common::{Scratch, project};

/// A copy of the fake `fgro` in a directory only root can search, so a child
/// that ran it after its drop reached it through the held descriptor alone.
/// `tag` must be unique within the suite, since its cases run in parallel.
fn fake_out_of_reach(tag: &str) -> (Scratch, PathBuf) {
    let scratch = Scratch::new(&format!("{tag}_fake_dir"));
    let fake = scratch.path().join("fgro");
    std::fs::copy(env!("CARGO_BIN_EXE_testing_fake_fgro"), &fake).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(std::fs::metadata(scratch.path()).unwrap().uid(), 0);
    (scratch, fake)
}

async fn eval(fgro: &Path, config: &Path, driver: &str) -> Result<EvalOutput, EvalError> {
    let pin = fgro_blake3(fgro, None).unwrap();
    eval_module(&EvalRequest {
        config_path: config,
        driver_js: driver,
        timeout: Duration::from_secs(20),
        fgro: FgroPin {
            path: fgro,
            expected_blake3: &pin,
            cache_dir: None,
        },
    })
    .await
}

/// The problem an eval was refused with, before any spawn; `tag` names the
/// fake's directory ([`fake_out_of_reach`]).
async fn refusal(tag: &str, config: &Path) -> RunAsProblem {
    let (_fake_dir, fake) = fake_out_of_reach(tag);
    match eval(&fake, config, "report").await {
        Err(EvalError::RunAs { problem, .. }) => problem,
        other => panic!("expected a refusal of who it runs as, got {other:?}"),
    }
}

/// A decimal id from the environment.
fn env_id(name: &str) -> Option<u32> {
    std::env::var(name).ok().map(|id| {
        id.parse()
            .unwrap_or_else(|_| panic!("{name} {id:?} is not a decimal id"))
    })
}

/// `uid`'s passwd entry: its home and primary group.
fn passwd(uid: u32) -> (PathBuf, u32) {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .unwrap()
        .unwrap_or_else(|| panic!("uid {uid} has no passwd entry"));
    (user.dir, user.gid.as_raw())
}

/// The `sudo` mode: root, with `SUDO_UID` and `SUDO_GID` naming a user other
/// than root. Returns that uid and gid.
fn sudo_mode() -> (u32, u32) {
    assert_eq!(
        common::effective_uid(),
        0,
        "run this suite as root (module docs)"
    );
    match (env_id("SUDO_UID"), env_id("SUDO_GID")) {
        (Some(uid), Some(gid)) if uid != 0 && gid != 0 => (uid, gid),
        other => panic!("the sudo_drop_ cases need SUDO_UID and SUDO_GID of a user, got {other:?}"),
    }
}

/// The owner mode: root, with no `SUDO_UID`. Returns the owner of Cargo's
/// target scratch directory, the user a project is chowned to.
fn owner_mode() -> u32 {
    assert_eq!(
        common::effective_uid(),
        0,
        "run this suite as root (module docs)"
    );
    assert!(
        std::env::var_os("SUDO_UID").is_none(),
        "the owner_drop_ cases need SUDO_UID unset (module docs)"
    );
    let owner = std::fs::metadata(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
        .uid();
    assert_ne!(owner, 0, "the target scratch directory is a user's");
    owner
}

/// Hand `dir` to `uid` and `gid`.
fn chown(dir: &Path, uid: u32, gid: u32) {
    std::os::unix::fs::chown(dir, Some(uid), Some(gid)).unwrap();
}

/// The fake's report of its uids and groups: each `Uid:` and `Gid:` field is
/// the dropped id, and no supplementary group is left.
fn assert_runs_as(output: &EvalOutput, project: &Path, uid: u32, gid: u32) {
    let report: serde_json::Value = serde_json::from_str(&output.value_json).unwrap();
    assert_eq!(
        report["ids"]["uid"],
        serde_json::json!([uid, uid, uid, uid]),
        "{report}"
    );
    assert_eq!(
        report["ids"]["gid"],
        serde_json::json!([gid, gid, gid, gid]),
        "{report}"
    );
    assert_eq!(report["ids"]["groups"], serde_json::json!([]), "{report}");
    // the working directory is entered after the drop
    assert_eq!(report["cwd"], project.to_str().unwrap());
    assert_eq!(report["argv"][0], "fgro");
}

/// This process's supplementary groups, which the child must not keep.
fn own_groups() -> Vec<String> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .unwrap()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
#[ignore = "needs root through sudo (module docs)"]
async fn sudo_drop_runs_the_child_as_the_owner_with_no_supplementary_groups() {
    let (uid, gid) = sudo_mode();
    let (scratch, config) = project("drop_sudo", "export default 1;\n");
    chown(scratch.path(), uid, gid);
    assert!(
        !own_groups().is_empty(),
        "the parent holds a supplementary group to drop"
    );
    let (_fake_dir, fake) = fake_out_of_reach("drop_sudo");
    let output = eval(&fake, &config, "report").await.unwrap();
    assert_runs_as(&output, scratch.path(), uid, gid);
}

#[tokio::test]
#[ignore = "needs root through sudo (module docs)"]
async fn sudo_drop_never_runs_a_root_owned_project_as_the_sudo_user() {
    let (uid, _) = sudo_mode();
    let (_scratch, config) = project("drop_sudo_root_owned", "export default 1;\n");
    assert_eq!(
        refusal("drop_sudo_root_owned", &config).await,
        RunAsProblem::RootOwnedProject {
            sudo_uid: Some(uid)
        }
    );
}

#[tokio::test]
#[ignore = "needs root through sudo (module docs)"]
async fn sudo_drop_refuses_a_project_the_user_cannot_search() {
    let (uid, gid) = sudo_mode();
    // a root-only directory above the project
    let outer = Scratch::new("drop_unsearchable_outer");
    let config = outer.path().join("p/config.ts");
    common::write(&config, "export default 1;\n");
    common::write(&outer.path().join("p/package.json"), r#"{"name":"p"}"#);
    let project = config.parent().unwrap();
    chown(project, uid, gid);
    std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let not_searchable = |dir: &Path| RunAsProblem::NotSearchable {
        uid,
        gid,
        dir: dir.display().to_string(),
    };
    assert_eq!(
        refusal("drop_unsearchable", &config).await,
        not_searchable(outer.path())
    );
    // the project itself, which its owner can read but not search
    std::fs::set_permissions(outer.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(project, std::fs::Permissions::from_mode(0o655)).unwrap();
    assert_eq!(
        refusal("drop_unsearchable", &config).await,
        not_searchable(project)
    );
}

/// Removes the files the home case wrote, on a failed assertion too.
struct Planted(Vec<PathBuf>);

impl Drop for Planted {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[tokio::test]
#[ignore = "needs root through sudo (module docs)"]
async fn sudo_drop_refuses_the_owner_s_home_as_the_project() {
    let (uid, _) = sudo_mode();
    if std::env::var_os("FUZ_EVAL_TEST_WRITE_HOME").as_deref() != Some("1".as_ref()) {
        eprintln!(
            "skipped: the home case writes into the sudo user's home; set \
             FUZ_EVAL_TEST_WRITE_HOME=1 to run it (module docs)"
        );
        return;
    }
    let (home, _) = passwd(uid);
    let home = std::fs::canonicalize(home).unwrap();
    assert_eq!(std::fs::metadata(&home).unwrap().uid(), uid);
    let package_json = home.join("package.json");
    let config = home.join(format!(".fuz_eval_uid_drop_{}.ts", std::process::id()));
    let mut planted = Planted(Vec::new());
    for (path, contents) in [
        (&package_json, r#"{"name":"home"}"#),
        (&config, "export default 1;\n"),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap_or_else(|error| {
                panic!(
                    "{}: {error} (the home case needs it absent)",
                    path.display()
                )
            });
        planted.0.push(path.clone());
        std::io::Write::write_all(&mut file, contents.as_bytes()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_eq!(
        refusal("drop_home", &config).await,
        RunAsProblem::HomeProject {
            uid,
            home: home.display().to_string(),
        }
    );
    drop(planted);
}

#[tokio::test]
#[ignore = "needs root through sudo and FUZ_EVAL_TEST_FGRO (module docs)"]
async fn sudo_drop_runs_real_fgro_as_the_owner() {
    let (uid, gid) = sudo_mode();
    let fgro = std::env::var_os("FUZ_EVAL_TEST_FGRO")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .expect("FUZ_EVAL_TEST_FGRO must name an fgro build by its absolute path");
    let (scratch, config) = project("drop_real", "export default {answer: 42};\n");
    chown(scratch.path(), uid, gid);
    let output = eval(
        &fgro,
        &config,
        "export default function (namespace) {\n\treturn namespace.default;\n}\n",
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.value_json, r#"{"answer":42}"#);
}

#[tokio::test]
#[ignore = "needs root with SUDO_UID unset (module docs)"]
async fn owner_drop_runs_the_child_as_the_owner_with_its_passwd_group() {
    let uid = owner_mode();
    let (_, gid) = passwd(uid);
    let (scratch, config) = project("drop_owner", "export default 1;\n");
    // the directory's group is root's: the passwd group is used, not it
    chown(scratch.path(), uid, 0);
    let (_fake_dir, fake) = fake_out_of_reach("drop_owner");
    let output = eval(&fake, &config, "report").await.unwrap();
    assert_runs_as(&output, scratch.path(), uid, gid);
}

#[tokio::test]
#[ignore = "needs root with SUDO_UID unset (module docs)"]
async fn owner_drop_refuses_a_root_owned_project() {
    owner_mode();
    let (_scratch, config) = project("drop_root_owned", "export default 1;\n");
    assert_eq!(
        refusal("drop_root_owned", &config).await,
        RunAsProblem::RootOwnedProject { sudo_uid: None }
    );
}

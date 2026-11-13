//! The client against a real `fgro`: the walls a config meets are fgro's, and
//! these cases pin the ones this crate's consumers rely on — what a config can
//! import, what it can reach, and how each refusal comes back.
//!
//! Marked `#[ignore]`: they need an `fgro` snapshot build, named by
//! `FUZ_EVAL_TEST_FGRO` as an absolute path. Run with
//! `FUZ_EVAL_TEST_FGRO=/abs/path/to/fgro cargo test -p fuz_eval --test real_fgro -- --ignored`.
//! Run with `--ignored` and no variable, every case fails rather than passing
//! untested.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use fuz_eval::{
    DumpOrigin, EvalError, EvalErrorKind, EvalFailure, EvalOutput, EvalRequest, FgroPin,
    TrustRootProblem, eval_module, fgro_blake3,
};

use common::{Scratch, project, write};

/// The driver every case sends: the config's default export is the value.
const DRIVER: &str = "export default function (namespace) {\n\treturn namespace.default;\n}\n";

/// The `fgro` under test and its pin, read once.
fn fgro() -> &'static (PathBuf, String) {
    static FGRO: OnceLock<(PathBuf, String)> = OnceLock::new();
    FGRO.get_or_init(|| {
        let path = std::env::var_os("FUZ_EVAL_TEST_FGRO").map(PathBuf::from);
        let Some(path) = path.filter(|path| path.is_absolute()) else {
            panic!(
                "FUZ_EVAL_TEST_FGRO must name an fgro snapshot build by its absolute path to run \
                 the real-fgro suite"
            );
        };
        let pin =
            fgro_blake3(&path, None).unwrap_or_else(|error| panic!("FUZ_EVAL_TEST_FGRO: {error}"));
        (path, pin)
    })
}

async fn eval_with(config: &Path, timeout: Duration) -> Result<EvalOutput, EvalError> {
    let (path, pin) = fgro();
    eval_module(&EvalRequest {
        config_path: config,
        driver_js: DRIVER,
        timeout,
        fgro: FgroPin {
            path,
            expected_blake3: pin,
            cache_dir: None,
        },
    })
    .await
}

async fn eval(config: &Path) -> Result<EvalOutput, EvalError> {
    eval_with(config, Duration::from_secs(20)).await
}

/// The value of an eval that must succeed.
async fn value(config: &Path) -> serde_json::Value {
    let output = eval(config)
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", config.display()));
    serde_json::from_str(&output.value_json).unwrap()
}

/// The failure of an eval that must fail as fgro reports it.
async fn failure(config: &Path) -> EvalFailure {
    match eval(config).await {
        Err(EvalError::Eval { failure, .. }) => *failure,
        other => panic!(
            "{}: expected an eval failure, got {other:?}",
            config.display()
        ),
    }
}

/// A config and its local import evaluate; the value comes back with sorted
/// keys, and the graph names both modules with the trust root as its project.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_config_and_its_local_import_evaluate() {
    let (scratch, config) = project(
        "real_ok",
        "import {n} from './dep.ts';\nexport default {zeta: n, alpha: [n + 1]};\n",
    );
    write(
        &scratch.path().join("dep.ts"),
        "export const n: number = 41;\n",
    );
    let output = eval(&config).await.unwrap();
    assert_eq!(output.value_json, r#"{"alpha":[42],"zeta":41}"#);
    assert_eq!(output.config_path, config);
    let graph = output.graph;
    assert_eq!(graph.local.project, scratch.path().to_str().unwrap());
    let ids: Vec<&str> = graph.modules.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["project:config.ts", "project:dep.ts"]);
    assert!(graph.modules.iter().all(|m| m.blake3.is_some()));
}

/// A type marker between the config and its project is walked past by both
/// walks: fgro's project and this crate's trust root agree.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_type_marker_between_the_config_and_its_project_is_walked_past() {
    let (scratch, _) = project("real_marker", "export default 0;\n");
    let config = scratch.path().join("deploy/zap.ts");
    write(&config, "export default 'deployed';\n");
    write(
        &scratch.path().join("deploy/package.json"),
        r#"{"type":"module"}"#,
    );
    let output = eval(&config).await.unwrap();
    assert_eq!(output.value_json, r#""deployed""#);
    assert_eq!(output.graph.local.project, scratch.path().to_str().unwrap());
}

/// A package linked into the project's `node_modules` from beside it — a path
/// dependency — evaluates, and the graph names it as linked, with its
/// directory among the box's roots.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_linked_path_dependency_evaluates() {
    let scratch = Scratch::new("real_linked");
    let project_dir = scratch.path().join("project");
    let lib = scratch.path().join("lib");
    write(&project_dir.join("package.json"), r#"{"name":"project"}"#);
    write(
        &lib.join("package.json"),
        r#"{"name":"lib","version":"1.0.0","type":"module","exports":"./index.js"}"#,
    );
    write(&lib.join("index.js"), "export const from_lib = 'lib';\n");
    std::fs::create_dir_all(project_dir.join("node_modules")).unwrap();
    std::fs::set_permissions(
        project_dir.join("node_modules"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::os::unix::fs::symlink(&lib, project_dir.join("node_modules/lib")).unwrap();
    let config = project_dir.join("zap.ts");
    write(
        &config,
        "import {from_lib} from 'lib';\nexport default from_lib;\n",
    );
    let output = eval(&config).await.unwrap();
    assert_eq!(output.value_json, r#""lib""#);
    let linked = output
        .graph
        .modules
        .iter()
        .find(|m| m.id == "linked:../lib/index.js")
        .unwrap_or_else(|| panic!("{:?}", output.graph.modules));
    assert_eq!(
        linked.origin,
        DumpOrigin::Package {
            name: "lib".into(),
            version: Some("1.0.0".into()),
            linked: true
        }
    );
    assert!(
        output
            .graph
            .local
            .box_roots
            .contains(&lib.to_str().unwrap().to_owned())
    );
}

/// A package planted in a `node_modules` above the project is never found: the
/// project's root bounds the package search, so the import doesn't resolve and
/// nothing of the planted package runs.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_package_planted_above_the_project_does_not_resolve() {
    let scratch = Scratch::new("real_planted");
    let project_dir = scratch.path().join("project");
    write(&project_dir.join("package.json"), r#"{"name":"project"}"#);
    let planted = scratch.path().join("node_modules/planted");
    write(
        &planted.join("package.json"),
        r#"{"name":"planted","type":"module","exports":"./index.js"}"#,
    );
    write(&planted.join("index.js"), "export default 'planted';\n");
    let config = project_dir.join("zap.ts");
    write(
        &config,
        "import planted from 'planted';\nexport default planted;\n",
    );
    let failure = failure(&config).await;
    assert_eq!(failure.kind, EvalErrorKind::Resolve, "{failure:?}");
    assert_eq!(failure.specifier.as_deref(), Some("planted"));
}

/// An import that doesn't resolve comes back as `resolve`, naming it.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn an_unresolved_import_is_a_resolve_failure_naming_it() {
    let (_scratch, config) = project(
        "real_unresolved",
        "import {x} from './missing.ts';\nexport default x;\n",
    );
    let failure = failure(&config).await;
    assert_eq!(failure.kind, EvalErrorKind::Resolve, "{failure:?}");
    assert_eq!(failure.specifier.as_deref(), Some("./missing.ts"));
}

/// A relative import out of the project, and a link inside the project to a
/// file outside it, are refused at resolution, naming the import, before the
/// outside file is read.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn an_import_out_of_the_project_is_refused() {
    let scratch = Scratch::new("real_outside");
    let project_dir = scratch.path().join("project");
    write(&project_dir.join("package.json"), r#"{"name":"project"}"#);
    write(
        &scratch.path().join("outside.ts"),
        "export const secret = 'outside';\n",
    );
    let relative = project_dir.join("relative.ts");
    write(
        &relative,
        "import {secret} from '../outside.ts';\nexport default secret;\n",
    );
    std::os::unix::fs::symlink(
        scratch.path().join("outside.ts"),
        project_dir.join("linked.ts"),
    )
    .unwrap();
    let through_link = project_dir.join("through_link.ts");
    write(
        &through_link,
        "import {secret} from './linked.ts';\nexport default secret;\n",
    );
    for (config, specifier) in [(relative, "../outside.ts"), (through_link, "./linked.ts")] {
        let failure = failure(&config).await;
        assert_eq!(
            (failure.kind, failure.specifier.as_deref()),
            (EvalErrorKind::Resolve, Some(specifier)),
            "{}: {failure:?}",
            config.display()
        );
        assert!(failure.message.contains("outside"), "{failure:?}");
    }
}

/// A config with no project root above it is refused before fgro runs: the
/// trust root's walk finds no `package.json` to set one.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_config_with_no_project_is_refused_before_fgro_runs() {
    let scratch = Scratch::new("real_no_project");
    let config = scratch.path().join("zap.ts");
    write(&config, "export default 1;\n");
    let error = eval(&config).await.unwrap_err();
    assert!(
        matches!(
            error,
            EvalError::TrustRoot {
                problem: TrustRootProblem::WalkStopped(_) | TrustRootProblem::NoProject,
                ..
            }
        ),
        "{error:?}"
    );
}

/// No import reaches past the disk under the project: a remote, `jsr:`, `npm:`,
/// `node:`, or `data:` specifier, and an absolute path or `file:` URL outside
/// the project, each fail to resolve, naming the import, before anything runs.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn an_import_past_the_project_s_disk_does_not_resolve() {
    for (tag, specifier) in [
        ("real_https", "https://example.com/x.js"),
        ("real_http", "http://127.0.0.1:9/x.js"),
        ("real_jsr", "jsr:@std/path"),
        ("real_npm", "npm:left-pad"),
        ("real_node", "node:fs"),
        ("real_data", "data:text/javascript,export default 1"),
        ("real_file_url", "file:///etc/passwd"),
        ("real_absolute", "/etc/passwd"),
    ] {
        let (_scratch, config) = project(
            tag,
            &format!("import x from {specifier:?};\nexport default String(x);\n"),
        );
        let failure = failure(&config).await;
        assert_eq!(
            (failure.kind, failure.specifier.as_deref()),
            (EvalErrorKind::Resolve, Some(specifier)),
            "{specifier}: {failure:?}"
        );
    }
}

/// An installed package's own bare import is bound by the project too: a
/// package planted in a `node_modules` above the project doesn't satisfy it.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn an_installed_package_s_bare_import_does_not_reach_above_the_project() {
    let scratch = Scratch::new("real_installed_planted");
    let project_dir = scratch.path().join("project");
    write(&project_dir.join("package.json"), r#"{"name":"project"}"#);
    let installed = project_dir.join("node_modules/installed");
    write(
        &installed.join("package.json"),
        r#"{"name":"installed","type":"module","exports":"./index.js"}"#,
    );
    write(
        &installed.join("index.js"),
        "import planted from 'planted';\nexport default planted;\n",
    );
    let planted = scratch.path().join("node_modules/planted");
    write(
        &planted.join("package.json"),
        r#"{"name":"planted","type":"module","exports":"./index.js"}"#,
    );
    write(&planted.join("index.js"), "export default 'planted';\n");
    let config = project_dir.join("zap.ts");
    write(
        &config,
        "import installed from 'installed';\nexport default installed;\n",
    );
    let failure = failure(&config).await;
    assert_eq!(
        (failure.kind, failure.specifier.as_deref()),
        (EvalErrorKind::Resolve, Some("planted")),
        "{failure:?}"
    );
}

/// A type-only import is erased with the types: one from a module that doesn't
/// exist still evaluates.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_type_only_import_of_a_missing_module_evaluates() {
    let (_scratch, config) = project(
        "real_import_type",
        "import type {Missing} from './missing.ts';\nconst x: Missing | number = 1;\nexport default x;\n",
    );
    assert_eq!(value(&config).await, serde_json::json!(1));
}

/// An import with attributes is refused at resolution, a JSON module's
/// included.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn import_attributes_are_refused() {
    let (scratch, config) = project(
        "real_attributes",
        "import data from './data.json' with {type: 'json'};\nexport default data;\n",
    );
    write(&scratch.path().join("data.json"), r#"{"a":1}"#);
    let failure = failure(&config).await;
    assert_eq!(failure.kind, EvalErrorKind::Resolve, "{failure:?}");
}

/// The clock and randomness throw, so a config can't read either.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn the_clock_and_randomness_throw() {
    for (tag, expression) in [
        ("real_now", "Date.now()"),
        ("real_date", "new Date().getTime()"),
        ("real_random", "Math.random()"),
        ("real_performance", "performance.now()"),
    ] {
        let (_scratch, config) = project(tag, &format!("export default {expression};\n"));
        let failure = failure(&config).await;
        assert_eq!(failure.kind, EvalErrorKind::ModuleThrew, "{expression}");
    }
}

/// No ambient authority is in scope: no `fetch`, no `Deno` or `process` (so no
/// environment, file writes, or subprocesses), no `WebAssembly` jitless; and an
/// `import()` — the remote-module channel — is refused whatever it names.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn no_ambient_authority_is_in_scope() {
    let (_scratch, config) = project(
        "real_authority",
        "const imported = await import('https://example.com/x.js').then(\n\
         \t() => 'loaded',\n\
         \t(error) => error instanceof TypeError,\n\
         );\n\
         export default {\n\
         \tfetch: typeof fetch,\n\
         \tdeno: typeof Deno,\n\
         \tprocess: typeof process,\n\
         \trequire: typeof require,\n\
         \twasm: typeof WebAssembly,\n\
         \timport_refused: imported,\n\
         };\n",
    );
    assert_eq!(
        value(&config).await,
        serde_json::json!({
            "fetch": "undefined",
            "deno": "undefined",
            "process": "undefined",
            "require": "undefined",
            "wasm": "undefined",
            "import_refused": true,
        })
    );
}

/// A config that throws is `module_threw`, with its message; its console output
/// is in the error's stderr.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_throwing_config_reports_its_message_and_console() {
    let (_scratch, config) = project(
        "real_throw",
        "console.log('said before throwing');\nthrow new Error('boom from config');\n",
    );
    let error = eval(&config).await.unwrap_err();
    let EvalError::Eval {
        failure, stderr, ..
    } = &error
    else {
        panic!("expected an eval failure, got {error:?}");
    };
    assert_eq!(failure.kind, EvalErrorKind::ModuleThrew);
    assert!(failure.message.contains("boom from config"), "{failure:?}");
    assert!(stderr.contains("said before throwing"), "{stderr}");
}

/// A config that never finishes is stopped by fgro's own timeout, reported as
/// its `timeout` kind well before the parent's backstop.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn fgro_s_timeout_stops_a_hanging_config() {
    let (_scratch, config) = project("real_hang", "while (true) {}\nexport default 1;\n");
    let error = eval_with(&config, Duration::from_millis(500))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, EvalError::Eval { failure, .. } if failure.kind == EvalErrorKind::Timeout),
        "{error:?}"
    );
}

/// A config that allocates past fgro's memory cap outside the heap — an
/// `ArrayBuffer` of 2 GiB — is stopped and reported as `memory`, not `heap`.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn an_allocation_past_the_memory_cap_is_a_memory_failure() {
    let (_scratch, config) = project(
        "real_memory",
        "const buffer = new ArrayBuffer(2 ** 31);\nexport default buffer.byteLength;\n",
    );
    let failure = failure(&config).await;
    assert_eq!(failure.kind, EvalErrorKind::Memory, "{failure:?}");
}

/// A config reached through a link is evaluated at its canonical path, which
/// is the envelope's entry.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_symlinked_config_is_evaluated_at_its_canonical_path() {
    let (scratch, config) = project("real_symlink", "export default 'real';\n");
    let link = scratch.path().join("link.ts");
    std::os::unix::fs::symlink(&config, &link).unwrap();
    let output = eval(&link).await.unwrap();
    assert_eq!(output.config_path, config);
    assert_eq!(output.value_json, r#""real""#);
}

/// The file evaluated is the file at the path given, whatever characters the
/// path holds: read as a URL, `config%41.ts` would be `configA.ts`, and a `#`
/// or `?` would end the path, each naming the impostor beside it.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn the_config_evaluated_is_the_file_named_whatever_its_path_holds() {
    let (scratch, _) = project("real_url", "export default 0;\n");
    for (real, impostor) in [
        ("config%41.ts", "configA.ts"),
        ("a#b/config.ts", "a"),
        ("q?x.ts", "q"),
    ] {
        let real_path = scratch.path().join(real);
        write(&real_path, "export default 'real';\n");
        write(
            &scratch.path().join(impostor),
            "export default 'impostor';\n",
        );
        let output = eval(&real_path)
            .await
            .unwrap_or_else(|error| panic!("{real}: {error}"));
        assert_eq!(output.value_json, r#""real""#, "{real}");
    }
}

/// A `deno.json` import map beside the config, and a parent `package.json`
/// claiming the project as a workspace, change nothing: no config file of
/// another tool is read, and the project's own `package.json` is its root.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn another_tool_s_config_files_change_nothing() {
    let scratch = Scratch::new("real_other_configs");
    write(
        &scratch.path().join("package.json"),
        r#"{"name":"workspace","workspaces":["project"]}"#,
    );
    let project_dir = scratch.path().join("project");
    write(&project_dir.join("package.json"), r#"{"name":"project"}"#);
    write(
        &project_dir.join("deno.json"),
        r#"{"imports":{"mapped":"./mapped.ts"}}"#,
    );
    write(&project_dir.join("mapped.ts"), "export default 'mapped';\n");
    let config = project_dir.join("zap.ts");
    write(
        &config,
        "import mapped from 'mapped';\nexport default mapped;\n",
    );
    let failure = failure(&config).await;
    assert_eq!(failure.kind, EvalErrorKind::Resolve, "{failure:?}");
    let plain = project_dir.join("plain.ts");
    write(&plain, "export default 'plain';\n");
    let output = eval(&plain).await.unwrap();
    assert_eq!(output.graph.local.project, project_dir.to_str().unwrap());
}

/// An npm workspace member is its own project: its `package.json` sets the
/// root, so the workspace's `node_modules` is outside it and never searched. A
/// member importing a package npm hoisted to the workspace root — a real
/// directory there, or a sibling member linked in — fails to resolve, naming
/// the import; a member importing only its own files evaluates. A member
/// whose `node_modules` links to the workspace's gets each package in it as a
/// linked one, and no more.
#[tokio::test]
#[ignore = "requires FUZ_EVAL_TEST_FGRO"]
async fn a_workspace_member_is_its_own_project() {
    let scratch = Scratch::new("real_workspace");
    let ws = scratch.path();
    write(
        &ws.join("package.json"),
        r#"{"name":"ws","private":true,"workspaces":["packages/*"]}"#,
    );
    let a = ws.join("packages/a");
    let b = ws.join("packages/b");
    write(
        &a.join("package.json"),
        r#"{"name":"a","version":"1.0.0","type":"module","dependencies":{"hoisted":"^1.0.0","b":"1.0.0"}}"#,
    );
    write(
        &b.join("package.json"),
        r#"{"name":"b","version":"1.0.0","type":"module","exports":"./index.js"}"#,
    );
    write(&b.join("index.js"), "export default 'b';\n");
    let hoisted = ws.join("node_modules/hoisted");
    write(
        &hoisted.join("package.json"),
        r#"{"name":"hoisted","version":"1.0.0","type":"module","exports":"./index.js"}"#,
    );
    write(&hoisted.join("index.js"), "export default 'hoisted';\n");
    // npm links each member into the workspace root's node_modules, relatively
    std::os::unix::fs::symlink("../packages/a", ws.join("node_modules/a")).unwrap();
    std::os::unix::fs::symlink("../packages/b", ws.join("node_modules/b")).unwrap();

    for (name, specifier) in [("hoisted.ts", "hoisted"), ("sibling.ts", "b")] {
        let config = a.join(name);
        write(
            &config,
            &format!("import x from {specifier:?};\nexport default x;\n"),
        );
        let error = eval(&config).await.unwrap_err();
        let EvalError::Eval { failure, .. } = &error else {
            panic!("{specifier}: expected an eval failure, got {error:?}");
        };
        let importer = format!("file://{}", config.display());
        assert_eq!(
            (
                failure.kind,
                failure.specifier.as_deref(),
                failure.importer.as_deref()
            ),
            (
                EvalErrorKind::Resolve,
                Some(specifier),
                Some(importer.as_str())
            ),
            "{failure:?}"
        );
        for part in [
            format!("cannot resolve '{specifier}' from {importer}"),
            format!("{}/package.json, which ends the search", a.display()),
            format!(
                "the node_modules beside {}/package.json is not searched",
                ws.display()
            ),
            format!("Fix: install it into {}/node_modules", a.display()),
        ] {
            assert!(failure.message.contains(&part), "{part}\n{failure:?}");
        }
        assert!(
            error.to_string().starts_with(&format!(
                "config evaluation failed for {} (resolve): ",
                config.display()
            )),
            "{error}"
        );
    }

    write(&a.join("local.ts"), "export const local = 'local';\n");
    let config = a.join("zap.ts");
    write(
        &config,
        "import {local} from './local.ts';\nexport default local;\n",
    );
    let output = eval(&config).await.unwrap();
    assert_eq!(output.value_json, r#""local""#);
    assert_eq!(output.graph.local.project, a.to_str().unwrap());
    let ids: Vec<&str> = output.graph.modules.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["project:local.ts", "project:zap.ts"]);

    // a member node_modules linked to the workspace's, as the fix message
    // invites, admits each package in it as a linked one, and no more
    std::os::unix::fs::symlink("../../node_modules", a.join("node_modules")).unwrap();
    let output = eval(&a.join("hoisted.ts")).await.unwrap();
    assert_eq!(output.value_json, r#""hoisted""#);
    let mut roots: Vec<&str> = output
        .graph
        .local
        .box_roots
        .iter()
        .map(String::as_str)
        .collect();
    roots.sort_unstable();
    let mut expected = [
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        hoisted.to_str().unwrap(),
    ];
    expected.sort_unstable();
    assert_eq!(roots, expected);
}

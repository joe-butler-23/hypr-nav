//! Model-checks `model/HyprNav.tla` with TLC so the protocol model cannot
//! drift from the build. The deeper `-2` bounds are run by hand (README).

use std::path::Path;
use std::process::Command;

fn tlc() -> Command {
    let on_path = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("tlc").is_file()));
    if on_path {
        Command::new("tlc")
    } else {
        let mut command = Command::new("nix");
        command.args(["shell", "nixpkgs#tlaplus", "--command", "tlc"]);
        command
    }
}

/// Configurations run one at a time, each in a private scratch directory:
/// TLC uses every core and unpacks its standard modules into the JVM's
/// temporary directory, which concurrent runs would otherwise share.
#[test]
fn routing_model_holds() {
    let model = Path::new(env!("CARGO_MANIFEST_DIR")).join("model");
    for config in ["close-1", "left-1", "right-1"] {
        let scratch =
            std::env::temp_dir().join(format!("hypr-nav-tlc-{config}-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let output = tlc()
            .env(
                "JAVA_TOOL_OPTIONS",
                format!("-Djava.io.tmpdir={}", scratch.display()),
            )
            .args(["-workers", "auto", "-metadir"])
            .arg(scratch.join("states"))
            .args(["-config", &format!("{config}.cfg"), "HyprNav.tla"])
            .current_dir(&model)
            .output()
            .expect("tlc runs");
        let _ = std::fs::remove_dir_all(&scratch);
        let log = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && log.contains("No error has been found"),
            "{config}:\n{log}"
        );
    }
}

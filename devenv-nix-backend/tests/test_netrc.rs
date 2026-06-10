//! `init_nix` must capture the pre-override `netrc-file` so the user's
//! credentials can be merged into the netrc devenv generates.

use devenv_core::{Config, NixOptions, NixSettings, StoreSettings};

#[test]
fn init_nix_captures_user_netrc_before_override() -> miette::Result<()> {
    let temp = tempfile::tempdir().expect("temp dir");
    let user_netrc = temp.path().join("user-netrc");
    std::fs::write(&user_netrc, "machine example.com\nlogin u\npassword p\n").expect("write netrc");
    let devenv_netrc = temp.path().join("devenv-netrc");

    let options = NixOptions {
        nix_options: vec!["netrc-file".into(), user_netrc.display().to_string()],
        ..Default::default()
    };
    let nix_settings = NixSettings::resolve(options, &Config::default());
    let store_settings = StoreSettings {
        netrc_path: Some(devenv_netrc.clone()),
        ..Default::default()
    };

    let init = devenv_nix_backend::backend::init_nix(&nix_settings, &store_settings)?;

    assert_eq!(init.user_netrc_file.as_ref(), Some(&user_netrc));
    assert_eq!(
        nix_bindings_util::settings::get("netrc-file").expect("get netrc-file"),
        devenv_netrc.to_str().unwrap()
    );
    Ok(())
}

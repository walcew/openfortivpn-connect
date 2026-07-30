use std::fs;
use std::path::Path;

fn main() {
    tauri_build::build();
    let version = env!("CARGO_PKG_VERSION");
    sync_frontend_constants();
    sync_tauri_conf();
    sync_package_json(version);
    sync_cargo_toml_metadata();
    sync_project_env(version);
}

fn sync_frontend_constants() {
    let path = Path::new("../src/generated/appConstants.ts");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let body = format!(
        "// Generated. Do not edit.\n\
export const PRODUCT_NAME = {product:?};\n\
export const APP_WINDOW_TITLE = {title:?};\n\
export const REPOSITORY_URL = {repo:?};\n",
        product = openvpngui_common::PRODUCT_NAME,
        title = openvpngui_common::APP_WINDOW_TITLE,
        repo = openvpngui_common::REPOSITORY_URL,
    );
    write_if_changed(path, &body);
}

fn sync_tauri_conf() {
    let path = Path::new("tauri.conf.json");
    let raw = fs::read_to_string(path).expect("read tauri.conf.json");
    let mut conf: serde_json::Value =
        serde_json::from_str(&raw).expect("parse tauri.conf.json");
    conf["productName"] = serde_json::Value::String(openvpngui_common::PRODUCT_NAME.into());
    conf["identifier"] =
        serde_json::Value::String(openvpngui_common::APP_BUNDLE_IDENTIFIER.into());
    if let Some(windows) = conf
        .pointer_mut("/app/windows")
        .and_then(|v| v.as_array_mut())
    {
        if let Some(main) = windows.first_mut() {
            main["title"] =
                serde_json::Value::String(openvpngui_common::APP_WINDOW_TITLE.into());
        }
    }
    if let Some(resources) = conf.pointer_mut("/bundle/resources").and_then(|v| v.as_object_mut())
    {
        resources.clear();
        resources.insert(
            format!("target/release/{}", openvpngui_common::HELPER_BINARY_NAME),
            serde_json::Value::String(openvpngui_common::HELPER_BINARY_NAME.into()),
        );
        resources.insert(
            format!("binaries/{}", openvpngui_common::OPENFORTIVPN_BINARY_NAME),
            serde_json::Value::String(openvpngui_common::OPENFORTIVPN_BINARY_NAME.into()),
        );
    }
    let body = format!("{}\n", serde_json::to_string_pretty(&conf).expect("serialize"));
    write_if_changed(path, &body);
}

fn sync_package_json(version: &str) {
    let path = Path::new("../package.json");
    let raw = fs::read_to_string(path).expect("read package.json");
    let helper_script = format!(
        "cd src-tauri && cargo build --release -p {}",
        openvpngui_common::HELPER_CRATE_NAME
    );
    let mut out = raw;
    out = replace_json_string_field(&out, "name", openvpngui_common::NPM_PACKAGE_NAME);
    out = replace_json_string_field(&out, "version", version);
    out = replace_json_script(&out, "build:helper", &helper_script);
    write_if_changed(path, &out);

    let lock = Path::new("../package-lock.json");
    if lock.exists() {
        let lock_raw = fs::read_to_string(lock).expect("read package-lock.json");
        let mut lock_out = replace_json_string_field(
            &lock_raw,
            "name",
            openvpngui_common::NPM_PACKAGE_NAME,
        );
        // Root package version appears twice near the top of the lockfile.
        lock_out = replace_json_string_field(&lock_out, "version", version);
        lock_out = replace_json_string_field(&lock_out, "version", version);
        write_if_changed(lock, &lock_out);
    }
}

fn sync_cargo_toml_metadata() {
    let path = Path::new("Cargo.toml");
    let raw = fs::read_to_string(path).expect("read Cargo.toml");
    let mut out = raw;
    out = replace_toml_string_field(&out, "name", openvpngui_common::APP_CRATE_NAME);
    out = replace_toml_string_field(
        &out,
        "description",
        openvpngui_common::PACKAGE_DESCRIPTION,
    );
    out = replace_toml_string_field(&out, "repository", openvpngui_common::REPOSITORY_URL);
    write_if_changed(path, &out);

    let helper = Path::new("helper/Cargo.toml");
    let helper_raw = fs::read_to_string(helper).expect("read helper/Cargo.toml");
    let mut helper_out = helper_raw;
    // package name + [[bin]] name
    helper_out = replace_toml_string_field(
        &helper_out,
        "name",
        openvpngui_common::HELPER_CRATE_NAME,
    );
    helper_out = replace_toml_string_field(
        &helper_out,
        "name",
        openvpngui_common::HELPER_BINARY_NAME,
    );
    write_if_changed(helper, &helper_out);
}

fn replace_toml_string_field(input: &str, field: &str, value: &str) -> String {
    let mut result = String::new();
    let mut replaced = false;
    for line in input.lines() {
        let trimmed = line.trim_start();
        let prefix = format!("{field} = ");
        if !replaced && trimmed.starts_with(&prefix) {
            let indent = &line[..line.len() - trimmed.len()];
            result.push_str(indent);
            result.push_str(&format!("{field} = {value:?}\n"));
            replaced = true;
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }
    if !replaced {
        panic!("Cargo.toml field `{field}` not found");
    }
    result
}

fn sync_project_env(version: &str) {
    let path = Path::new("../project.env");
    let body = format!(
        "# Generated. Do not edit.\n\
PRODUCT_NAME={product}\n\
APP_WINDOW_TITLE={title}\n\
PACKAGE_DESCRIPTION={description}\n\
REPOSITORY_SLUG={slug}\n\
REPOSITORY_URL={repo}\n\
NPM_PACKAGE_NAME={npm}\n\
APP_CRATE_NAME={app_crate}\n\
HELPER_CRATE_NAME={helper_crate}\n\
HELPER_BINARY_NAME={helper_bin}\n\
HOMEBREW_CASK={cask}\n\
HOMEBREW_TAP_REPO={tap}\n\
DMG_ASSET_PATTERN={dmg}\n\
APP_VERSION={version}\n",
        product = shell_single_line(openvpngui_common::PRODUCT_NAME),
        title = shell_single_line(openvpngui_common::APP_WINDOW_TITLE),
        description = shell_single_line(openvpngui_common::PACKAGE_DESCRIPTION),
        slug = openvpngui_common::REPOSITORY_SLUG,
        repo = openvpngui_common::REPOSITORY_URL,
        npm = openvpngui_common::NPM_PACKAGE_NAME,
        app_crate = openvpngui_common::APP_CRATE_NAME,
        helper_crate = openvpngui_common::HELPER_CRATE_NAME,
        helper_bin = openvpngui_common::HELPER_BINARY_NAME,
        cask = openvpngui_common::HOMEBREW_CASK,
        tap = openvpngui_common::HOMEBREW_TAP_REPO,
        dmg = openvpngui_common::DMG_ASSET_PATTERN,
        version = version,
    );
    write_if_changed(path, &body);
}

fn shell_single_line(s: &str) -> String {
    s.replace('\n', " ").replace('"', "")
}

fn replace_json_string_field(input: &str, field: &str, value: &str) -> String {
    let key = format!("\"{field}\"");
    let mut result = String::new();
    let mut replaced = false;
    for line in input.lines() {
        if !replaced {
            if let Some(idx) = line.find(&key) {
                let after = &line[idx + key.len()..];
                if after.trim_start().starts_with(':') {
                    let indent_end = line.len() - line.trim_start().len();
                    let comma = if line.trim_end().ends_with(',') {
                        ","
                    } else {
                        ""
                    };
                    result.push_str(&line[..indent_end]);
                    result.push_str(&format!("\"{field}\": {value:?}{comma}\n"));
                    replaced = true;
                    continue;
                }
            }
        }
        result.push_str(line);
        result.push('\n');
    }
    if !replaced {
        panic!("JSON field `{field}` not found");
    }
    result
}

fn replace_json_script(input: &str, script: &str, value: &str) -> String {
    let pattern = format!("\"{script}\"");
    let mut result = String::new();
    let mut replaced = false;
    for line in input.lines() {
        if !replaced && line.contains(&pattern) {
            let indent_end = line.len() - line.trim_start().len();
            let comma = if line.trim_end().ends_with(',') { "," } else { "" };
            result.push_str(&line[..indent_end]);
            result.push_str(&format!("\"{script}\": {value:?}{comma}\n"));
            replaced = true;
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }
    if !replaced {
        panic!("package.json script `{script}` not found");
    }
    result
}

fn write_if_changed(path: &Path, body: &str) {
    let prev = fs::read_to_string(path).unwrap_or_default();
    if prev != body {
        fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
    }
}

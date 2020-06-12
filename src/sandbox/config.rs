use crate::errors::*;
use dirs;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use toml;

#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct Config {
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct SandboxConfig {
    pub user: Option<String>,
    pub chroot: Option<String>,
}

pub fn find() -> Option<String> {
    let mut paths = vec![
        String::from("/etc/sniffglue.conf"),
        String::from("/usr/local/etc/sniffglue.conf"),
    ];

    if let Some(home) = dirs::config_dir() {
        let path = home.join(Path::new("sniffglue.conf"));

        if let Some(path) = path.to_str() {
            paths.push(path.into());
        }
    };

    for config_path in paths {
        if Path::new(&config_path).exists() {
            return Some(config_path);
        }
    }

    None
}

pub fn load(path: &str) -> Result<Config> {
    let content = fs::read_to_string(path)?;
    let config = toml::from_str(&content)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let config: Config = toml::from_str(
            r#"
            [sandbox]
            user = "foo"
            chroot = "/var/empty"
            "#,
        )
        .unwrap();

        assert_eq!(
            Config {
                sandbox: SandboxConfig {
                    user: Some(String::from("foo")),
                    chroot: Some(String::from("/var/empty")),
                },
            },
            config
        );
    }
}

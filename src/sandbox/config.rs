use std::io::{self, Read};
use std::fs::File;
use std::path::Path;
use toml;
use dirs;

#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct Config {
    pub sandbox: SandboxConfig,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct SandboxConfig {
    pub user: Option<String>,
    pub chroot: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Toml(toml::de::Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Error {
        Error::Toml(err)
    }
}

pub fn find() -> Option<String> {
    let mut paths = vec![String::from("/etc/sniffglue.conf")];

    // paths.push(String::from("sniffglue.conf"));

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

pub fn load(path: &str) -> Result<Config, Error> {
    let mut file = File::open(path)?;

    let mut content = String::new();
    file.read_to_string(&mut content)?;

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
        ).unwrap();

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

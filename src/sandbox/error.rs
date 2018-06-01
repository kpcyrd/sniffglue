use sandbox::config;
use nix;
use std;

#[derive(Debug)]
pub enum Error {
    Seccomp(SeccompError),
    Config(config::Error),
    Nix(nix::Error),
    Io(std::io::Error),
    Chroot,
    InvalidUser,
    FFI,
}

#[derive(Debug)]
pub enum SeccompError {
    FFI,
}

impl From<SeccompError> for Error {
    fn from(err: SeccompError) -> Error {
        Error::Seccomp(err)
    }
}

impl From<config::Error> for Error {
    fn from(err: config::Error) -> Error {
        Error::Config(err)
    }
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::Nix(err)
    }
}

impl From<std::io::Error> for Error  {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

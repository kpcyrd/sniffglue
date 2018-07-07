use sandbox::config;
use nix;
use syscallz;
use std;

#[derive(Debug)]
pub enum Error {
    Seccomp(syscallz::Error),
    Config(config::Error),
    Nix(nix::Error),
    Io(std::io::Error),
    Chroot,
    InvalidUser,
    FFI,
}

impl From<syscallz::Error> for Error {
    fn from(err: syscallz::Error) -> Error {
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

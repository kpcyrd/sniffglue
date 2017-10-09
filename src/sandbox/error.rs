use sandbox::config;

#[derive(Debug)]
pub enum Error {
    Seccomp(SeccompError),
    Config(config::Error),
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
    fn from(err:config::Error) -> Error {
        Error::Config(err)
    }
}

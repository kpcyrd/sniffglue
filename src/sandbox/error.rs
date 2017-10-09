#[derive(Debug)]
pub enum Error {
    Seccomp(SeccompError),
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

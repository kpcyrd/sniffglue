pub use log::{debug, info, warn};
pub use failure::{Error, ResultExt, bail};
pub type Result<T> = ::std::result::Result<T, Error>;

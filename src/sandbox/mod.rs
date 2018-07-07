use std::fs;
use std::env;
use std::os::unix::fs::MetadataExt;

use users;
use nix;
use nix::unistd::{Uid, Gid, setuid, setgid, getgroups, setgroups};

pub mod config;
mod error;
#[cfg(target_os="linux")]
pub mod seccomp;

pub use self::error::Error;


pub fn activate_stage1() -> Result<(), Error> {
    #[cfg(target_os="linux")]
    seccomp::activate_stage1()?;

    info!("stage 1/2 is active");

    Ok(())
}

pub fn chroot(path: &str) -> Result<(), Error> {
    let metadata = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return Err(Error::Chroot),
    };

    if !metadata.is_dir() {
        error!("chroot target is no directory");
        return Err(Error::Chroot);
    }

    if metadata.uid() != 0 {
        error!("chroot target isn't owned by root");
        return Err(Error::Chroot);
    }

    if metadata.mode() & 0o22 != 0 {
        error!("chroot is writable by group or world");
        return Err(Error::Chroot);
    }

    nix::unistd::chroot(path)?;
    env::set_current_dir("/")?;
    Ok(())
}

pub fn id() -> String {
    let uid = users::get_current_uid();
    let euid = users::get_effective_uid();
    let gid = users::get_current_gid();
    let egid = users::get_effective_gid();
    let groups = getgroups().unwrap();

    format!(
        "uid={:?} euid={:?} gid={:?} egid={:?} groups={:?}",
        uid,
        euid,
        gid,
        egid,
        groups
    )
}

fn apply_config(config: config::Config) -> Result<(), Error> {
    debug!("got config: {:?}", config);

    let user = match config.sandbox.user {
        Some(user) => {
            let user = match users::get_user_by_name(&user) {
                Some(user) => user,
                None => return Err(Error::InvalidUser),
            };
            Some((user.uid(), user.primary_group_id()))
        },
        _ => None,
    };

    let is_root = Uid::current().is_root();

    match config.sandbox.chroot.as_ref() {
        Some(path) if is_root => {
            info!("starting chroot: {:?}", path);
            chroot(path)?;
            info!("successfully chrooted");
        },
        _ => (),
    }

    if is_root {
        match user {
            Some((uid, gid)) => {
                info!("id: {}", id());
                info!("setting uid to {:?}", uid);
                setgroups(&[])?;
                setgid(Gid::from_raw(gid))?;
                setuid(Uid::from_raw(uid))?;
                info!("id: {}", id());
            },
            None => {
                warn!("executing as root!");
            },
        }
    } else {
        info!("can't drop privileges, executing as {}", id());
    }

    Ok(())
}

pub fn activate_stage2() -> Result<(), Error> {
    let config = config::find().map_or_else(
        || {
            warn!("couldn't find config");
            Ok(config::Config::default())
        },
        |config_path| {
            config::load(&config_path)
        },
    )?;

    apply_config(config)?;

    #[cfg(target_os="linux")]
    seccomp::activate_stage2()?;

    info!("stage 2/2 is active");

    Ok(())
}

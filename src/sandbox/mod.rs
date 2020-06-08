use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;

use nix;
use nix::unistd::{setgid, setuid, Gid, Uid};
use users;
// TODO: drop the condition after nix added getgroups/setgroups support to osx
#[cfg(target_os = "linux")]
use nix::unistd::{getgroups, setgroups};

pub mod config;
#[cfg(target_os = "linux")]
pub mod seccomp;

pub use crate::errors::*;

pub fn activate_stage1() -> Result<()> {
    #[cfg(target_os = "linux")]
    seccomp::activate_stage1()?;

    info!("stage 1/2 is active");

    Ok(())
}

pub fn chroot(path: &str) -> Result<()> {
    let metadata = fs::metadata(path)?;

    if !metadata.is_dir() {
        bail!("chroot target is no directory");
    }

    if metadata.uid() != 0 {
        bail!("chroot target isn't owned by root");
    }

    if metadata.mode() & 0o22 != 0 {
        bail!("chroot is writable by group or world");
    }

    nix::unistd::chroot(path)?;
    env::set_current_dir("/")?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn id() -> String {
    let uid = users::get_current_uid();
    let euid = users::get_effective_uid();
    let gid = users::get_current_gid();
    let egid = users::get_effective_gid();
    let groups = getgroups().unwrap();

    format!(
        "uid={:?} euid={:?} gid={:?} egid={:?} groups={:?}",
        uid, euid, gid, egid, groups,
    )
}

// TODO: use the other id function everywhere after nix added getgroups/setgroups support to osx
#[cfg(not(target_os = "linux"))]
pub fn id() -> String {
    let uid = users::get_current_uid();
    let euid = users::get_effective_uid();
    let gid = users::get_current_gid();
    let egid = users::get_effective_gid();

    format!(
        "uid={:?} euid={:?} gid={:?} egid={:?}",
        uid, euid, gid, egid,
    )
}

fn apply_config(config: config::Config) -> Result<()> {
    debug!("got config: {:?}", config);

    let user = match config.sandbox.user {
        Some(user) => {
            let user = match users::get_user_by_name(&user) {
                Some(user) => user,
                None => bail!("Invalid sandbox user"),
            };
            Some((user.uid(), user.primary_group_id()))
        }
        _ => None,
    };

    let is_root = Uid::current().is_root();

    match config.sandbox.chroot.as_ref() {
        Some(path) if is_root => {
            info!("starting chroot: {:?}", path);
            chroot(path)?;
            info!("successfully chrooted");
        }
        _ => (),
    }

    if is_root {
        match user {
            Some((uid, gid)) => {
                info!("id: {}", id());
                info!("setting uid to {:?}", uid);
                // TODO: drop the condition after nix added getgroups/setgroups support to osx
                #[cfg(target_os = "linux")]
                setgroups(&[])?;
                setgid(Gid::from_raw(gid))?;
                setuid(Uid::from_raw(uid))?;
                info!("id: {}", id());
            }
            None => {
                warn!("executing as root!");
            }
        }
    } else {
        info!("can't drop privileges, executing as {}", id());
    }

    Ok(())
}

pub fn activate_stage2() -> Result<()> {
    let config = if let Some(config_path) = config::find() {
        config::load(&config_path)?
    } else {
        warn!("couldn't find config");
        config::Config::default()
    };

    apply_config(config)?;

    #[cfg(target_os = "linux")]
    seccomp::activate_stage2()?;

    info!("stage 2/2 is active");

    Ok(())
}

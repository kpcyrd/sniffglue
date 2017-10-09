use std::fs;
use std::env;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;

use users;
use libc::{self, uid_t, gid_t};

pub mod config;
mod error;

pub use self::error::Error;

cfg_if! {
    if #[cfg(all(target_os="linux", any(target_arch="x86_64")))] {
        pub mod seccomp;
    } else if #[cfg(target_os="linux")] {
        #[path="seccomp_unsupported.rs"]
        pub mod seccomp;
    }
}

pub fn activate_stage1() -> Result<(), Error> {
    if cfg!(target_os="linux") {
        seccomp::activate_stage1()?;
    }

    info!("stage 1/2 is active");

    Ok(())
}

pub fn chroot(path: &str) -> Result<(), Error> {
    let metadata = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return Err(Error::Chroot),
    };

    if ! metadata.is_dir() {
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

    let path = CString::new(path).unwrap();
    let ret = unsafe { libc::chroot(path.as_ptr()) };

    if ret != 0 {
        Err(Error::Chroot)
    } else {
        match env::set_current_dir("/") {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::Chroot),
        }
    }
}

pub fn setreuid(uid: uid_t) -> Result<(), Error> {
    let ret = unsafe { libc::setreuid(uid, uid) };

    if ret != 0 {
        Err(Error::FFI)
    } else {
        Ok(())
    }
}

pub fn setregid(gid: gid_t) -> Result<(), Error> {
    let ret = unsafe { libc::setregid(gid, gid) };

    if ret != 0 {
        Err(Error::FFI)
    } else {
        Ok(())
    }
}

pub fn setgroups(groups: Vec<gid_t>) -> Result<(), Error> {
    let ret = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };

    if ret < 0 {
        Err(Error::FFI)
    } else {
        Ok(())
    }
}

pub fn getgroups() -> Result<Vec<gid_t>, ()> {
    let size = 128;
    let mut gids: Vec<gid_t> = Vec::with_capacity(size as usize);

    let ret = unsafe { libc::getgroups(size, gids.as_mut_ptr()) };

    if ret < 0 {
        Err(())
    } else {
        let groups = (0..ret)
            .map(|i| {
                unsafe { gids.get_unchecked(i as usize) }.to_owned()
            }).collect();
        Ok(groups)
    }
}

pub fn id() -> String {
    let uid = users::get_current_uid();
    let euid = users::get_effective_uid();
    let gid = users::get_current_gid();
    let egid = users::get_effective_gid();
    let groups = getgroups().unwrap();

    format!("uid={:?} euid={:?} gid={:?} egid={:?} groups={:?}",
        uid,
        euid,
        gid,
        egid,
        groups)
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

    match config.sandbox.chroot {
        Some(path) => {
            info!("starting chroot: {:?}", path);
            chroot(&path)?;
            info!("successfully chrooted");
        },
        _ => (),
    };

    match user {
        Some((uid, gid)) => {
            info!("id: {}", id());
            info!("setting uid to {:?}", uid);
            setgroups(Vec::new())?;
            setregid(gid)?;
            setreuid(uid)?;
            info!("id: {}", id());
        },
        None => (),
    };

    Ok(())
}

pub fn activate_stage2() -> Result<(), Error> {
    match config::find() {
        Some(config_path) => match config::load(&config_path) {
            Ok(config) => apply_config(config)?,
            Err(err) => {
                warn!("couldn't load config: {:?}", err);
            },
        },
        None => (),
    };

    if users::get_current_uid() == 0 {
        warn!("current user is root!");
    }

    if cfg!(target_os="linux") {
        seccomp::activate_stage2()?;
    }

    info!("stage 2/2 is active");

    Ok(())
}

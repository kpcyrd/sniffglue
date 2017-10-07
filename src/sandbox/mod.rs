use std::fs;
use std::env;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;

use users;
use libc::{self, uid_t, gid_t};
use seccomp_sys::*;

pub mod config;

#[cfg(all(target_os="linux", target_arch="x86_64"))]
#[path="syscalls/linux-x86_64.rs"]
mod syscalls;

use self::syscalls::SYSCALL;

impl SYSCALL {
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

pub struct Context {
    ctx: *mut scmp_filter_ctx,
}

impl Context {
    fn init() -> Result<Context, ()> {
        let ctx = unsafe { seccomp_init(SCMP_ACT_KILL) };

        if ctx.is_null() {
            return Err(());
        }

        Ok(Context {
            ctx,
        })
    }

    fn allow_syscall(&mut self, syscall: SYSCALL) -> Result<(), ()> {
        debug!("seccomp: allowing syscall={:?}", syscall);
        let ret = unsafe { seccomp_rule_add(self.ctx, SCMP_ACT_ALLOW, syscall.as_i32(), 0) };

        if ret != 0 {
            Err(())
        } else {
            Ok(())
        }
    }

    fn load(&self) -> Result<(), ()> {
        let ret = unsafe { seccomp_load(self.ctx) };

        if ret != 0 {
            Err(())
        } else {
            Ok(())
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            seccomp_release(self.ctx)
        };
    }
}

pub fn activate_stage1(danger_disable_seccomp: &bool) -> Result<(), ()> {
    let voided = *danger_disable_seccomp;

    if !danger_disable_seccomp {
        let mut ctx = Context::init()?;

        ctx.allow_syscall(SYSCALL::futex)?;
        ctx.allow_syscall(SYSCALL::read)?;
        ctx.allow_syscall(SYSCALL::write)?;
        ctx.allow_syscall(SYSCALL::open)?;
        ctx.allow_syscall(SYSCALL::close)?;
        ctx.allow_syscall(SYSCALL::stat)?;
        ctx.allow_syscall(SYSCALL::fstat)?;
        ctx.allow_syscall(SYSCALL::lstat)?;
        ctx.allow_syscall(SYSCALL::poll)?;
        ctx.allow_syscall(SYSCALL::lseek)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::mmap)?;
        ctx.allow_syscall(SYSCALL::mprotect)?;
        ctx.allow_syscall(SYSCALL::munmap)?;
        ctx.allow_syscall(SYSCALL::ioctl)?;
        ctx.allow_syscall(SYSCALL::socket)?;
        ctx.allow_syscall(SYSCALL::connect)?;
        ctx.allow_syscall(SYSCALL::sendto)?;
        ctx.allow_syscall(SYSCALL::recvfrom)?;
        ctx.allow_syscall(SYSCALL::sendmsg)?;
        ctx.allow_syscall(SYSCALL::recvmsg)?;
        ctx.allow_syscall(SYSCALL::bind)?;
        ctx.allow_syscall(SYSCALL::getsockname)?;
        ctx.allow_syscall(SYSCALL::setsockopt)?;
        ctx.allow_syscall(SYSCALL::getsockopt)?;
        ctx.allow_syscall(SYSCALL::clone)?;
        ctx.allow_syscall(SYSCALL::uname)?;
        ctx.allow_syscall(SYSCALL::fcntl)?;
        ctx.allow_syscall(SYSCALL::getdents)?;
        ctx.allow_syscall(SYSCALL::chdir)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::getuid)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::getgid)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::geteuid)?;
        ctx.allow_syscall(SYSCALL::getegid)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::setresuid)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::setresgid)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::getgroups)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::setgroups)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::getresuid)?;
        ctx.allow_syscall(SYSCALL::getresgid)?;
        ctx.allow_syscall(SYSCALL::sigaltstack)?;
        ctx.allow_syscall(SYSCALL::prctl)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::chroot)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::sched_getaffinity)?;
        ctx.allow_syscall(SYSCALL::clock_getres)?;
        ctx.allow_syscall(SYSCALL::exit_group)?;
        ctx.allow_syscall(SYSCALL::set_robust_list)?;
        ctx.allow_syscall(SYSCALL::openat)?;
        ctx.allow_syscall(SYSCALL::seccomp)?; // needed for stage2
        ctx.allow_syscall(SYSCALL::getrandom)?;

        ctx.load()?;
    } else {
        warn!("stage 1/2: seccomp has been disabled!");
    }

    if voided {
        warn!("stage 1/2 is active, but some things have been disabled!");
    } else {
        info!("stage 1/2 is active");
    }

    Ok(())
}

pub fn chroot(path: &str) -> Result<(), ()> {
    let metadata = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return Err(()),
    };

    if ! metadata.is_dir() {
        error!("chroot target is no directory");
        return Err(());
    }

    if metadata.uid() != 0 {
        error!("chroot target isn't owned by root");
        return Err(());
    }

    if metadata.mode() & 0o22 != 0 {
        error!("chroot is writable by group or world");
        return Err(());
    }

    let path = CString::new(path).unwrap();
    let ret = unsafe { libc::chroot(path.as_ptr()) };

    if ret != 0 {
        Err(())
    } else {
        match env::set_current_dir("/") {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

pub fn setreuid(uid: uid_t) -> Result<(), ()> {
    let ret = unsafe { libc::setreuid(uid, uid) };

    if ret != 0 {
        Err(())
    } else {
        Ok(())
    }
}

pub fn setregid(gid: gid_t) -> Result<(), ()> {
    let ret = unsafe { libc::setregid(gid, gid) };

    if ret != 0 {
        Err(())
    } else {
        Ok(())
    }
}

pub fn setgroups(groups: Vec<gid_t>) -> Result<(), ()> {
    let ret = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };

    if ret < 0 {
        Err(())
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

pub fn activate_stage2(danger_disable_seccomp: &bool) -> Result<(), ()> {
    let voided = *danger_disable_seccomp;

    match config::find() {
        Some(config_path) => match config::load(&config_path) {
            Ok(config) => {
                debug!("got config: {:?}", config);

                let user = match config.sandbox.user {
                    Some(user) => {
                        let user = match users::get_user_by_name(&user) {
                            Some(user) => user,
                            None => return Err(()),
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
            },
            Err(err) => {
                warn!("couldn't load config: {:?}", err);
            },
        },
        None => (),
    };

    if users::get_current_uid() == 0 {
        warn!("current user is root!");
    }

    if !danger_disable_seccomp {
        let mut ctx = Context::init()?;

        ctx.allow_syscall(SYSCALL::futex)?;
        ctx.allow_syscall(SYSCALL::read)?;
        ctx.allow_syscall(SYSCALL::write)?;
        // ctx.allow_syscall(SYSCALL::open)?;
        ctx.allow_syscall(SYSCALL::close)?;
        // ctx.allow_syscall(SYSCALL::stat)?;
        // ctx.allow_syscall(SYSCALL::fstat)?;
        // ctx.allow_syscall(SYSCALL::lstat)?;
        ctx.allow_syscall(SYSCALL::poll)?;
        ctx.allow_syscall(SYSCALL::mmap)?;
        ctx.allow_syscall(SYSCALL::mprotect)?;
        ctx.allow_syscall(SYSCALL::munmap)?;
        // ctx.allow_syscall(SYSCALL::ioctl)?;
        // ctx.allow_syscall(SYSCALL::socket)?;
        // ctx.allow_syscall(SYSCALL::connect)?;
        // ctx.allow_syscall(SYSCALL::sendto)?;
        // ctx.allow_syscall(SYSCALL::recvfrom)?;
        // ctx.allow_syscall(SYSCALL::sendmsg)?;
        // ctx.allow_syscall(SYSCALL::recvmsg)?;
        // ctx.allow_syscall(SYSCALL::bind)?;
        // ctx.allow_syscall(SYSCALL::getsockname)?;
        // ctx.allow_syscall(SYSCALL::setsockopt)?;
        // ctx.allow_syscall(SYSCALL::getsockopt)?;
        ctx.allow_syscall(SYSCALL::clone)?;
        // ctx.allow_syscall(SYSCALL::uname)?;
        // ctx.allow_syscall(SYSCALL::fcntl)?;
        // ctx.allow_syscall(SYSCALL::getdents)?;
        // ctx.allow_syscall(SYSCALL::geteuid)?;
        // ctx.allow_syscall(SYSCALL::getresuid)?;
        // ctx.allow_syscall(SYSCALL::getresgid)?;
        ctx.allow_syscall(SYSCALL::sigaltstack)?;
        ctx.allow_syscall(SYSCALL::sched_getaffinity)?;
        // ctx.allow_syscall(SYSCALL::clock_getres)?;
        ctx.allow_syscall(SYSCALL::exit_group)?;
        ctx.allow_syscall(SYSCALL::set_robust_list)?;
        // ctx.allow_syscall(SYSCALL::openat)?;
        // ctx.allow_syscall(SYSCALL::getrandom)?;

        ctx.load()?;
    } else {
        warn!("stage 2/2: seccomp has been disabled!");
    }

    if voided {
        warn!("stage 2/2 is active, but some things have been disabled");
    } else {
        info!("stage 2/2 is active");
    }

    Ok(())
}

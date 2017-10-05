use seccomp_sys::*;

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

pub fn activate_stage1() -> Result<(), ()> {
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
    ctx.allow_syscall(SYSCALL::geteuid)?;
    ctx.allow_syscall(SYSCALL::getresuid)?;
    ctx.allow_syscall(SYSCALL::getresgid)?;
    ctx.allow_syscall(SYSCALL::sigaltstack)?;
    ctx.allow_syscall(SYSCALL::prctl)?; // needed for stage2
    ctx.allow_syscall(SYSCALL::sched_getaffinity)?;
    ctx.allow_syscall(SYSCALL::clock_getres)?;
    ctx.allow_syscall(SYSCALL::exit_group)?;
    ctx.allow_syscall(SYSCALL::set_robust_list)?;
    ctx.allow_syscall(SYSCALL::openat)?;
    ctx.allow_syscall(SYSCALL::seccomp)?; // needed for stage2
    ctx.allow_syscall(SYSCALL::getrandom)?;

    ctx.load()?;

    Ok(())
}

pub fn activate_stage2() -> Result<(), ()> {
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

    Ok(())
}

use libc;

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum Syscall {
    read                = libc::SYS_read                as isize,
    write               = libc::SYS_write               as isize,
    open                = libc::SYS_open                as isize,
    close               = libc::SYS_close               as isize,
    stat                = libc::SYS_stat                as isize,
    fstat               = libc::SYS_fstat               as isize,
    lstat               = libc::SYS_lstat               as isize,
    poll                = libc::SYS_poll                as isize,
    ppoll               = libc::SYS_ppoll               as isize,
    lseek               = libc::SYS_lseek               as isize,
    mmap                = libc::SYS_mmap                as isize,
    mprotect            = libc::SYS_mprotect            as isize,
    munmap              = libc::SYS_munmap              as isize,
    rt_sigprocmask      = libc::SYS_rt_sigprocmask      as isize,
    ioctl               = libc::SYS_ioctl               as isize,
    readv               = libc::SYS_readv               as isize,
    socket              = libc::SYS_socket              as isize,
    connect             = libc::SYS_connect             as isize,
    sendto              = libc::SYS_sendto              as isize,
    recvfrom            = libc::SYS_recvfrom            as isize,
    sendmsg             = libc::SYS_sendmsg             as isize,
    recvmsg             = libc::SYS_recvmsg             as isize,
    bind                = libc::SYS_bind                as isize,
    getsockname         = libc::SYS_getsockname         as isize,
    setsockopt          = libc::SYS_setsockopt          as isize,
    getsockopt          = libc::SYS_getsockopt          as isize,
    clone               = libc::SYS_clone               as isize,
    uname               = libc::SYS_uname               as isize,
    fcntl               = libc::SYS_fcntl               as isize,
    getdents            = libc::SYS_getdents            as isize,
    chdir               = libc::SYS_chdir               as isize,
    getuid              = libc::SYS_getuid              as isize,
    getgid              = libc::SYS_getgid              as isize,
    geteuid             = libc::SYS_geteuid             as isize,
    getegid             = libc::SYS_getegid             as isize,
    setresuid           = libc::SYS_setresuid           as isize,
    setresgid           = libc::SYS_setresgid           as isize,
    getgroups           = libc::SYS_getgroups           as isize,
    setgroups           = libc::SYS_setgroups           as isize,
    getresuid           = libc::SYS_getresuid           as isize,
    getresgid           = libc::SYS_getresgid           as isize,
    sigaltstack         = libc::SYS_sigaltstack         as isize,
    prctl               = libc::SYS_prctl               as isize,
    chroot              = libc::SYS_chroot              as isize,
    futex               = libc::SYS_futex               as isize,
    sched_getaffinity   = libc::SYS_sched_getaffinity   as isize,
    getdents64          = libc::SYS_getdents64          as isize,
    clock_getres        = libc::SYS_clock_getres        as isize,
    exit_group          = libc::SYS_exit_group          as isize,
    set_robust_list     = libc::SYS_set_robust_list     as isize,
    openat              = libc::SYS_openat              as isize,
    newfstatat          = libc::SYS_newfstatat          as isize,
    seccomp             = libc::SYS_seccomp             as isize,
    getrandom           = libc::SYS_getrandom           as isize,
    pipe                = libc::SYS_pipe                as isize,
    wait4               = libc::SYS_wait4               as isize,
}

impl Syscall {
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

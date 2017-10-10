use sandbox::error::SeccompError;

pub fn activate_stage1() -> Result<(), SeccompError> {
    warn!("seccomp is unsupported on this architecture, please file a bug!");
    warn!("no sandbox enabled");

    Ok(())
}

pub fn activate_stage2() -> Result<(), SeccompError> {
    warn!("seccomp is unsupported on this architecture, please file a bug!");
    warn!("no sandbox enabled");

    Ok(())
}

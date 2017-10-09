pub fn activate_stage1() -> Result<(), ()> {
    warn!("seccomp is unsupported on this architecture, please file a bug!");
    warn!("no sandbox enabled");

    Ok(())
}

pub fn activate_stage2() -> Result<(), ()> {
    warn!("seccomp is unsupported on this architecture, please file a bug!");
    warn!("no sandbox enabled");

    Ok(())
}

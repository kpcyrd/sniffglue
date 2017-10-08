pub fn activate_stage1(_danger_disable_seccomp: &bool) -> Result<(), ()> {
    warn!("seccomp is unsupported on this architecture, please file a bug!");
    warn!("no sandbox enabled");

    Ok(())
}

pub fn activate_stage2(_danger_disable_seccomp: &bool) -> Result<(), ()> {
    warn!("seccomp is unsupported on this architecture, please file a bug!");
    warn!("no sandbox enabled");

    Ok(())
}

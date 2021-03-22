#[macro_use] extern crate boxxy;
extern crate sniffglue;
extern crate env_logger;

fn stage1(sh: &mut boxxy::Shell, _args: Vec<String>) -> Result<(), boxxy::Error> {
    shprintln!(sh, "[*] starting stage1");
    sniffglue::sandbox::activate_stage1(false).unwrap();
    shprintln!(sh, "[+] activated!");
    Ok(())
}

fn stage2(sh: &mut boxxy::Shell, _args: Vec<String>) -> Result<(), boxxy::Error> {
    shprintln!(sh, "[*] starting stage2");
    sniffglue::sandbox::activate_stage2(false).unwrap();
    shprintln!(sh, "[+] activated!");
    Ok(())
}

fn main() {
    env_logger::init();

    println!("stage1        activate sandbox stage1/2");
    println!("stage2        activate sandbox stage2/2");

    let toolbox = boxxy::Toolbox::new().with(vec![
            ("stage1", stage1),
            ("stage2", stage2),
        ]);
    boxxy::Shell::new(toolbox).run()
}

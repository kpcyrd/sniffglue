extern crate boxxy;
extern crate sniffglue;
extern crate env_logger;

fn stage1(_args: Vec<String>) -> Result<(), boxxy::Error> {
    println!("[*] starting stage1");
    sniffglue::sandbox::activate_stage1().unwrap();
    println!("[+] activated!");
    Ok(())
}

fn stage2(_args: Vec<String>) -> Result<(), boxxy::Error> {
    println!("[*] starting stage2");
    sniffglue::sandbox::activate_stage2().unwrap();
    println!("[+] activated!");
    Ok(())
}

fn main() {
    env_logger::init().unwrap();

    println!("stage1        activate sandbox stage1/2");
    println!("stage2        activate sandbox stage2/2");

    let toolbox = boxxy::Toolbox::new().with(vec![
            ("stage1", stage1),
            ("stage2", stage2),
        ]);
    boxxy::Shell::new(toolbox).run()
}

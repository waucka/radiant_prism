extern crate gcc;
extern crate pkg_config;

fn main() {
    let flatpak_conf = pkg_config::Config::new().atleast_version("0.8.5").probe("flatpak").unwrap();
    let mut gcc_conf = gcc::Config::new();
    gcc_conf.file("utillib-c/utillib.c");

    for pth in flatpak_conf.include_paths {
        gcc_conf.include(pth);
    }

    gcc_conf.compile("libutillib.a");
}

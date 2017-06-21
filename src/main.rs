extern crate regex;
extern crate libc;
extern crate pgs_files;

mod sysutils;
mod flatpak;

use sysutils::{get_procs, get_network_interfaces, get_fs_mounts};
use flatpak::{get_flatpak_installed_packages, FlatpakError};

fn main() {
    for proc_struct in get_procs().unwrap() {
        println!("{} {}", proc_struct.pid, proc_struct.name);
    }

    for netif in get_network_interfaces().unwrap() {
        println!("{}{} {}", if netif.is_loopback { "*" } else { " " }, netif.name, netif.macaddr);
    }

    for passwd_entry in pgs_files::passwd::get_all_entries() {
        println!("{} {} {}", passwd_entry.uid, passwd_entry.gid, passwd_entry.name)
    }

    for mount in get_fs_mounts().unwrap() {
        println!("{} {} {}", mount.device, mount.fstype, mount.dir);
    }

    let (pkgs, err) = get_flatpak_installed_packages();
    for pkg in pkgs {
        println!("{}", pkg.origin);
    }
    match err {
        FlatpakError::None => (),
        FlatpakError::Incomplete => println!("The above flatpak list is incomplete."),
        FlatpakError::Unknown => println!("The above flatpak list is probably incomplete, but who knows what happened?"),
    }
}

extern crate regex;
extern crate libc;
extern crate pgs_files;

use std::fs::{read_dir, File, read_link};
use std::path::Path;
use std::io;
use std::io::prelude::*;
use std::ptr;
use regex::Regex;

pub struct FSMount {
    pub device: String,
    pub dir: String,
    pub fstype: String,
    pub opts: Vec<String>,
    pub freq: i32,
    pub passno: i32,
}

fn get_fs_mounts() -> io::Result<Vec<FSMount>> {
    let mut mounts = Vec::new();
    let mtab_file = File::open("/etc/mtab")?;
    let reader = io::BufReader::new(&mtab_file);
    for line_maybe in reader.lines() {
        match line_maybe {
            Ok(line) => {
                let parts: Vec<&str> = line.split(' ').collect();
                if parts.len() < 6 {
                    continue;
                }
                let freq_int = match parts[4].parse() {
                    Ok(num) => num,
                    Err(_) => 0,
                };
                let passno_int = match parts[5].parse() {
                    Ok(num) => num,
                    Err(_) => 0,
                };
                mounts.push(FSMount{
                    device: String::from(parts[0]),
                    dir: String::from(parts[1]),
                    fstype: String::from(parts[2]),
                    opts: parts[3].split(',').map(|x| String::from(x)).collect(),
                    freq: freq_int,
                    passno: passno_int,
                });
            },
            Err(_) => (),
        }
    }
    return Ok(mounts);
}

// Might be wrong!
const IFNAMSIZ: usize = 16;

#[repr(C)]
struct netif_t {
  name: [libc::c_uchar; IFNAMSIZ],
  macaddr: [libc::c_uchar; 6],
  is_loopback: libc::c_uchar,
}


#[link(name = "utillib", kind = "static")]
extern {
    fn free_netifs(netifs: *mut *mut netif_t) -> libc::c_int;
    fn enum_netifs(netifs: *mut *mut netif_t, num_netifs: *mut libc::size_t) -> libc::c_int;
}

pub struct NetworkInterface {
    pub name: String,
    pub macaddr: String,
    pub is_loopback: bool,
}

fn get_network_interfaces() -> Result<Vec<NetworkInterface>, i32> {
    let mut netifs = Vec::new();
    unsafe {
        let mut netifs_buffer: *mut netif_t = ptr::null_mut();
        let mut num_netifs: libc::size_t = 0;
        let enum_result = enum_netifs(&mut netifs_buffer as *mut *mut netif_t, &mut num_netifs as *mut libc::size_t);
        if enum_result != 0 {
            return Err(enum_result);
        }
        let netifs_c = Vec::from_raw_parts(netifs_buffer, num_netifs as usize, num_netifs as usize);
        for netif in netifs_c {
            // Why is there junk after the lo and \0 in the name of the loopback interface?
            let mut end_of_name = IFNAMSIZ;
            for i in 0..IFNAMSIZ {
                if netif.name[i] == 0 {
                    end_of_name = i;
                    break;
                }
            }
            let netif_name = match String::from_utf8(netif.name[0..end_of_name].to_vec()) {
                Ok(name_str) => name_str,
                Err(_) => String::from("ERROR"),
            };
            let netif_macaddr = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                        netif.macaddr[0],
                                        netif.macaddr[1],
                                        netif.macaddr[2],
                                        netif.macaddr[3],
                                        netif.macaddr[4],
                                        netif.macaddr[5],
            );
            netifs.push(NetworkInterface{
                name: netif_name,
                macaddr: netif_macaddr,
                is_loopback: netif.is_loopback != 0,
            });
        }
        free_netifs(&mut netifs_buffer as *mut *mut netif_t);
    }
    return Ok(netifs);
}

pub struct Process {
    pub name: String,
    pub cmdline: String,
    pub exe: String,
    pub cwd: String,
    pub pid: i32,
}

fn build_cmdline(cmdline_path: &Path) -> io::Result<String> {
    let mut file = File::open(cmdline_path)?;
    let mut cmdline = String::new();
    file.read_to_string(&mut cmdline)?;
    return Ok(cmdline.replace('\0', " "));
}

fn file_contents(file_path: &Path) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    return Ok(contents);
}

fn build_proc(pid: i32) -> Process {
    let path = format!("/proc/{}", pid);
    let path = Path::new(&path);

    let name_path = path.join("comm");
    let name = match file_contents(&name_path) {
        Ok(name_str) => String::from(name_str.trim()),
        Err(_) => String::from("ERROR"),
    };
    let cwd_path = path.join("cwd");
    let cwd = match read_link(cwd_path) {
        Ok(pth) => pth.into_os_string().into_string().unwrap(),
        Err(_) => String::from("ERROR"),
    };
    let exe_path = path.join("exe");
    let exe = match read_link(exe_path) {
        Ok(pth) => pth.into_os_string().into_string().unwrap(),
        Err(_) => String::from("ERROR"),
    };
    let cmdline_path = path.join("cmdline");
    let cmdline = match build_cmdline(&cmdline_path) {
        Ok(cmdline_str) => cmdline_str,
        Err(_) => String::from("ERROR"),
    };

    Process{
        name: name,
        cmdline: cmdline,
        exe: exe,
        cwd: cwd,
        pid: pid,
    }
}

pub fn get_procs() -> io::Result<Vec<Process>> {
    let mut procs = Vec::new();
    for entry in read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        // This had damn well better not fail.
        let dirname = path.file_name().unwrap().to_str().unwrap();
        // Same here.
        let pid_re = Regex::new(r"^\d+$").unwrap();
        if pid_re.is_match(dirname) {
            // This should never, ever fail.
            let pid = dirname.parse::<i32>().unwrap();

            procs.push(build_proc(pid));
        }
    }

    return Ok(procs);
}

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
}

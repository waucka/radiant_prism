extern crate gcc;

fn main() {
    gcc::Config::new()
        .file("utillib-c/utillib.c")
        .include("utillib-c")
        .compile("libutillib.a");
}

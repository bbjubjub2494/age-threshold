use std::env;
use std::io;

fn main() -> io::Result<()> {
    three::run(&three::parse(env::args_os())?)
}

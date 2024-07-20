use super::{DecryptOpts, EncryptOpts, Opts};

use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Data {
    tmp_dir: TempDir,
    key1: PathBuf,
    key2: PathBuf,
    key3: PathBuf,
    _2outof3: PathBuf,
    output: PathBuf,
}

fn setup() -> io::Result<Data> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let key1 = tmp_path.join("key1.txt");
    let key2 = tmp_path.join("key2.txt");
    let key3 = tmp_path.join("key3.txt");
    let _2outof3 = tmp_path.join("2outof3.age");
    let output = tmp_path.join("output");
    File::create(&key1)?.write_all(include_bytes!("data/key1.txt"))?;
    File::create(&key2)?.write_all(include_bytes!("data/key2.txt"))?;
    File::create(&key3)?.write_all(include_bytes!("data/key3.txt"))?;
    File::create(&_2outof3)?.write_all(include_bytes!("data/2outof3.age"))?;
    Ok(Data {
        tmp_dir,
        key1,
        key2,
        key3,
        _2outof3,
        output,
    })
}

#[test]
fn test_2outof3_decrypt_sample() -> io::Result<()> {
    let Data {
        tmp_dir,
        key1,
        key2,
        _2outof3,
        output,
        ..
    } = setup()?;
    super::run(&Opts::Decrypt(DecryptOpts {
        input: Some(_2outof3),
        identities: vec![key1, key2],
        output: Some(output.clone()),
    }))?;
    let mut buf = String::new();
    File::open(output)?.read_to_string(&mut buf)?;
    assert_eq!(&buf[..], "Hello world!\n");
    tmp_dir.close()
}

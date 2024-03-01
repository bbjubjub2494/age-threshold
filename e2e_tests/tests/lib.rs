use std::fs::{File,remove_file};
use std::io::Write;
use std::process::Command;

use tempfile::tempdir;

#[test]
fn scenario() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = tempdir()?;
    std::env::set_current_dir(&tmp_dir)?;

    fn plugin() -> Command {
        Command::new("age-plugin-threshold")
    }
    fn keygen() -> Command {
        Command::new("age-keygen")
    }
    fn age() -> Command {
        Command::new("age")
    }

    for i in 1..=3 {
        let mut cmd = keygen();
        cmd.arg("-o").arg(format!("key{}.txt", i));
        assert!(cmd.status()?.success());
    }

    let mut recipients = vec![];
    for i in 1..=3 {
        let mut cmd = keygen();
        cmd.arg("-y").arg(format!("key{}.txt", i));
        let recipient = String::from_utf8(cmd.output()?.stdout)?;
        recipients.push(recipient.trim().to_string());
    }

    {
        let mut cmd = plugin();
        cmd
            .arg("-t").arg("2")
            .stdout(File::create("test.age")?);
        for r in recipients {
            cmd.args(&["-r", &r]);
        }
        assert!(cmd.status()?.success());
    }

    remove_file("key2.txt")?;

    {
        let mut cmd = plugin();
        cmd.arg("-d").arg("-i").arg("key1.wrap.txt").arg("-i").arg("key3.wrap.txt").arg("test.age");
        dbg!(cmd.output()?.stdout);
        assert!(cmd.output()?.stdout == b"test");
    }

    tmp_dir.close()?;

    Ok(())
}

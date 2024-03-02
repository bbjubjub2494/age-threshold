use std::fs::{remove_file, File};
use std::io::Write;
use std::process::{Command, Stdio};

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
        cmd.arg("-t")
            .arg("2")
            .stdin(Stdio::piped())
            .stdout(File::create("test.age")?);
        for r in recipients {
            cmd.args(&["-r", &r]);
        }
        let mut child = cmd.spawn()?;
        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        let t = std::thread::spawn(move || stdin.write_all(b"test"));
        assert!(child.wait()?.success());
        t.join().unwrap()?;
    }

    remove_file("key2.txt")?;

    {
        let mut cmd = plugin();
        cmd.arg("-d")
            .arg("-i")
            .arg("key1.txt")
            .arg("-i")
            .arg("key3.txt")
            .stdin(File::open("test.age")?);
        assert!(cmd.output()?.stdout == b"test");
    }

    tmp_dir.close()?;

    Ok(())
}

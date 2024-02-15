use std::os::unix::ffi::OsStrExt;
use std::ffi::OsStr;
use std::fs::File;
use std::process::Command;
use tempfile::tempdir;
use std::io::Write;

#[test]
fn scenario() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = tempdir()?;
    std::env::set_current_dir(&tmp_dir)?;

    fn plugin() -> Command{
        Command::new("age-plugin-threshold")
    }
    fn keygen() -> Command{Command::new("age-keygen")}
    fn age   () -> Command{ Command::new("age")}

    {
    let mut cmd = keygen();
    cmd.arg("-o").arg("key.txt");
    assert!(cmd.status()?.success());
    }

    {
    let mut cmd = plugin();
    cmd.arg("wrap").arg("key.txt").stdout(File::create("key.wrap.txt")?);
    assert!(cmd.status()?.success());
    }

    let recipient =
    {
    let mut cmd = keygen();
    cmd.arg("-y").arg("key.txt");
 String::from_utf8(cmd.output()?.stdout)?
    };

    {
    let mut cmd = plugin();
    cmd.arg("build-recipient").arg("-t 1").arg(recipient.trim()).stdout(File::create("recipient.txt")?);
    assert!(cmd.status()?.success());
    }

    {
    let mut cmd = age();
    let mut stdin = File::create("test")?;
    stdin.write_all(b"test")?;
    drop(stdin);
    cmd.arg("-R").arg("recipient.txt").arg("-o").arg("test.age").stdin(File::open("test")?);
    assert!(cmd.status()?.success());
    }

    {
    let mut cmd = age();
    cmd.arg("-d").arg("-i").arg("key.wrap.txt").arg("test.age");
    assert!(cmd.status()?.success());
    }


    tmp_dir.close()?;

    Ok(())
}

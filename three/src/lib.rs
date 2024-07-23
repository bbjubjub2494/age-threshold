use age::cli_common::file_io;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::string::String;

use age_threshold::types::{AgeIdentity, AgeRecipient};

use clap::*;

#[derive(Debug, PartialEq, Eq)]
pub enum Opts {
    Encrypt(EncryptOpts),
    Decrypt(DecryptOpts),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct EncryptOpts {
    pub threshold: Option<u32>,
    pub recipients: Vec<String>,
    pub recipients_files: Vec<PathBuf>,
    pub armor: bool,
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct DecryptOpts {
    pub identities: Vec<PathBuf>,
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
}

pub fn parse<I, T>(args: I) -> io::Result<Opts>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cmd = command!().args(&[
                             arg!(-e --encrypt "Encrypt the input to the output. Default if omitted."),
                             arg!(-d --decrypt "Decrypt the input to the output."),
                             arg!(-a --armor "Encrypt to a PEM encoded format."),
                             arg!(-t --threshold [THRESHOLD]   "Threshold number of recipients needed to decrypt.").value_parser(value_parser!(u32)),
                             arg!(-r --recipient [RECIPIENT] ... "Encrypt to the specified RECIPIENT. Can be repeated."),
                             arg!(-R --"recipients-file" [PATH] ... "Encrypt to recipients listed at PATH. Can be repeated.").value_parser(value_parser!(PathBuf)),
                             arg!(-i --identity [PATH] ... "Use the identity file at PATH. Can be repeated.").value_parser(value_parser!(PathBuf)),
                             arg!(-o --output [PATH] "Write the result to the file at path OUTPUT.").value_parser(value_parser!(PathBuf)),
                             arg!([INPUT] "Read the input from the file at path INPUT.").value_parser(value_parser!(PathBuf)),
    ]);

    let m = cmd.get_matches_from(args);
    let encrypt = m.get_flag("encrypt");
    let decrypt = m.get_flag("decrypt");
    let armor = m.get_flag("armor");
    let threshold = m.get_one::<u32>("threshold").copied();
    let recipients = match m.get_many::<String>("recipient") {
        None => vec![],
        Some(v) => v.cloned().collect(),
    };
    let recipients_files = match m.get_many::<PathBuf>("recipients-file") {
        None => vec![],
        Some(v) => v.cloned().collect(),
    };
    let identities = match m.get_many::<PathBuf>("identity") {
        None => vec![],
        Some(v) => v.cloned().collect(),
    };
    let output = m.get_one::<PathBuf>("output").cloned();
    let input = m.get_one::<PathBuf>("INPUT").cloned();

    if encrypt && decrypt {
        return Err(io::Error::other(
            "cannot encrypt and decrypt at the same time",
        ));
    }
    Ok(if decrypt {
        Opts::Decrypt(DecryptOpts {
            identities,
            output,
            input,
        })
    } else {
        Opts::Encrypt(EncryptOpts {
            threshold,
            recipients,
            recipients_files,
            armor,
            input,
            output,
        })
    })
}

pub fn run(opts: &Opts) -> io::Result<()> {
    match &opts {
        Opts::Encrypt(opts) => encrypt(opts),
        Opts::Decrypt(opts) => decrypt(opts),
    }
}

fn encrypt(opts: &EncryptOpts) -> io::Result<()> {
    let mut recipients = vec![];
    for r in &opts.recipients {
        recipients.push(AgeRecipient::from_bech32(r).map_err(io::Error::other)?);
    }
    for f in &opts.recipients_files {
        let lines = read_text_file(f)?;
        for l in lines {
            recipients.push(AgeRecipient::from_bech32(l.as_str()).map_err(io::Error::other)?);
        }
    }
    let n = recipients.len() as u32;
    let t = opts.threshold.unwrap_or(n / 2 + 1);

    let (mut input, mut output) =
        set_up_io(&opts.input, &opts.output, file_io::OutputFormat::Binary)?;
    age_threshold::encrypt(&recipients, t, &mut input, &mut output)
}

fn decrypt(opts: &DecryptOpts) -> io::Result<()> {
    let mut identities = vec![];
    for id in &opts.identities {
        let lines = read_text_file(id)?;
        identities.push(AgeIdentity::from_bech32(&lines[0]).map_err(io::Error::other)?);
    }

    let (mut input, mut output) =
        set_up_io(&opts.input, &opts.output, file_io::OutputFormat::Unknown)?;
    age_threshold::decrypt(&identities, &mut input, &mut output)
}

fn set_up_io(
    input: &Option<PathBuf>,
    output: &Option<PathBuf>,
    format: file_io::OutputFormat,
) -> io::Result<(file_io::InputReader, file_io::OutputWriter)> {
    let input = file_io::InputReader::new(input.as_ref().map(|p| p.to_string_lossy().to_string()))?;
    let output = file_io::OutputWriter::new(
        output.as_ref().map(|p| p.to_string_lossy().to_string()),
        true,
        format,
        0o644,
        input.is_terminal(),
    )?;
    Ok((input, output))
}

fn read_text_file(path: &Path) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let mut v = vec![];
    for l in io::BufReader::new(file).lines() {
        let line = l?;
        if !line.starts_with('#') {
            v.push(line.trim().to_string());
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_examples() -> io::Result<()> {
        assert_eq!(parse(["three"])?, Opts::Encrypt(EncryptOpts::default()));
        assert_eq!(
            parse(["three", "-e"])?,
            Opts::Encrypt(EncryptOpts::default())
        );
        assert!(parse(["three", "-e", "-d"]).is_err());
        assert_eq!(
            parse(["three", "-eR", "some_file"])?,
            Opts::Encrypt(EncryptOpts {
                recipients_files: vec!["some_file".into()],
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "-r", "age1fake"])?,
            Opts::Encrypt(EncryptOpts {
                recipients: vec!["age1fake".to_string()],
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "-r", "age2fake", "-r", "age1fake"])?,
            Opts::Encrypt(EncryptOpts {
                recipients: vec!["age2fake".to_string(), "age1fake".to_string()],
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "-t", "2", "-r", "age2fake", "-r", "age1fake"])?,
            Opts::Encrypt(EncryptOpts {
                recipients: vec!["age2fake".to_string(), "age1fake".to_string()],
                threshold: Some(2),
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "input_file"])?,
            Opts::Encrypt(EncryptOpts {
                input: Some("input_file".into()),
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "input_file", "-o", "output_file"])?,
            Opts::Encrypt(EncryptOpts {
                input: Some("input_file".into()),
                output: Some("output_file".into()),
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "-d", "input_file", "-o", "output_file"])?,
            Opts::Decrypt(DecryptOpts {
                input: Some("input_file".into()),
                output: Some("output_file".into()),
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "-d", "-i", "identityfile1"])?,
            Opts::Decrypt(DecryptOpts {
                identities: vec!["identityfile1".into()],
                ..Default::default()
            })
        );
        assert_eq!(
            parse(["three", "-d", "-i", "identityfile1", "-i", "identityfile2"])?,
            Opts::Decrypt(DecryptOpts {
                identities: vec!["identityfile1".into(), "identityfile2".into()],
                ..Default::default()
            })
        );
        Ok(())
    }
}

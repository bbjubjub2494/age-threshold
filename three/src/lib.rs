use age::cli_common::file_io;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::string::String;

use age_threshold::types::{AgeIdentity, AgeRecipient};

pub enum Opts {
    Encrypt(EncryptOpts),
    Decrypt(DecryptOpts),
}
pub struct EncryptOpts {
    pub threshold: Option<u32>,
    pub identities: Vec<PathBuf>,
    pub recipients: Vec<String>,
    pub recipients_files: Vec<PathBuf>,
    pub armor: bool,
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
}
pub struct DecryptOpts {
    pub identities: Vec<PathBuf>,
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
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
    for _i in &opts.identities {
        todo!();
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

use std::io;
use std::path::{Path, PathBuf};

use clap::*;

use age_threshold::cmd::*;

fn main() -> io::Result<()> {
    let cmd = command!().args(&[
                             arg!(-e --encrypt "Encrypt the input to the output. Default if omitted."),
                             arg!(-d --decrypt "Decrypt the input to the output."),
                             arg!(-a --armor "Encrypt to a PEM encoded format."),
                             arg!(-t --threshold [THRESHOLD]   "Threshold number of recipients needed to decrypt.").value_parser(value_parser!(u32)),
                             arg!(-r --recipient [RECIPIENT] ... "Encrypt to the specified RECIPIENT. Can be repeated."),
                             arg!(-R --recipients-file [PATH] ... "Encrypt to recipients listed at PATH. Can be repeated."),
                             arg!(-i --identity [PATH] ... "Use the identity file at PATH. Can be repeated."),
                             arg!(-o --output [PATH] "Write the result to the file at path OUTPUT."),
                             arg!([INPUT] "Read the input from the file at path INPUT."),
    ]);

    let m = cmd.get_matches();
    let encrypt = m.get_flag("encrypt");
    let decrypt = m.get_flag("decrypt");
    let armor = m.get_flag("armor");
    let threshold = m.get_one::<u32>("threshold").copied();
    let recipients = match m.get_many::<String>("recipient") {
        None => vec![],
        Some(v) => v.cloned().collect(),
    };
    let recipients_files = match m.get_many::<PathBuf>("recipients_files") {
        None => vec![],
        Some(v) => v.cloned().collect(),
    };
    let identities = match m.get_many::<PathBuf>("identity") {
        None => vec![],
        Some(v) => v.cloned().collect(),
    };
    let output = m.get_one::<PathBuf>("output").cloned();
    let input = m.get_one::<PathBuf>("input").cloned();

    if encrypt && decrypt {
        return Err(io::Error::other(
            "cannot encrypt and decrypt at the same time",
        ));
    }
    if decrypt {
        run(&Opts::Decrypt(DecryptOpts {
            identities,
            output,
            input,
        }))
    } else {
        run(&Opts::Encrypt(EncryptOpts {
            threshold,
            identities,
            recipients,
            recipients_files,
            armor,
            input,
            output,
        }))
    }
}

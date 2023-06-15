use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    print_new_identity,
    recipient::{self, RecipientPluginV1},
    Callbacks, run_state_machine,
};
use clap::{arg, command, value_parser};
use std::collections::HashMap;
use std::io;

#[derive(Debug, Default)]
struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8]
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        todo!()
    }
}

type SecretShare = Vec<u8>;


#[derive(Debug, Default)]
struct IdentityPlugin {
    shares: Vec<SecretShare>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8]
    ) -> Result<(), identity::Error> {
        todo!()
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        todo!()
    }
}

fn main() -> io::Result<()> {
    let cmd = command!()
        .arg(
            arg!(--"age-plugin" <state_machine> "run the given age plugin state machine")
            )
        .get_matches();

    if let Some(state_machine) = cmd.get_one::<String>("age-plugin") {
        // The plugin was started by an age client; run the state machine.
        run_state_machine(
            &state_machine,
            RecipientPlugin::default,
            IdentityPlugin::default,
        )?;
        return Ok(());
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.

    Ok(())
}

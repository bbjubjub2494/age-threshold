use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::{arg, command};
use std::collections::HashMap;
use std::io;

use age_core::secrecy::ExposeSecret;
use age_plugin_threshold::crypto;
use age_plugin_threshold::threshold_recipient::ThresholdRecipient;

#[derive(Debug, Default)]
struct RecipientPlugin {
    recipients: Vec<ThresholdRecipient>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != "threshold" {
            return Err(recipient::Error::Recipient {
                index: index,
                message: "not age-plugin-threshold".into(),
            });
        }
        self.recipients
            .push(ThresholdRecipient::from_rlp(bytes).unwrap());
        Ok(())
    }

    fn add_identity(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        Ok(Ok(self
            .recipients
            .iter()
            .map(|r| {
                file_keys
                    .iter()
                    .map(|fk| {
                        let shares = crypto::share_secret(fk, r.t.into(), r.recipients.len());
                        // TODO: wrap shares
                        Stanza {
                            tag: "threshold".into(),
                            args: vec![],
                            body: rlp::encode(
                                &shares
                                    .iter()
                                    .flat_map(|s| s.expose_secret().clone())
                                    .collect::<Vec<_>>(),
                            )
                            .to_vec(), // FIXME: not space efficient
                        }
                    })
                    .collect()
            })
            .collect()))
    }
}

#[derive(Debug, Default)]
struct IdentityPlugin {}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), identity::Error> {
        todo!()
    }

    fn unwrap_file_keys(
        &mut self,
        _file_keys: Vec<Vec<Stanza>>,
        _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        todo!()
    }
}

fn main() -> io::Result<()> {
    let cmd = command!()
        .arg(arg!(--"age-plugin" <state_machine> "run the given age plugin state machine"))
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

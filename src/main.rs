use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::{arg, command};
use std::collections::HashMap;
use std::io;

use age_core::secrecy::Secret;
use age_plugin_threshold::crypto;
use age_plugin_threshold::threshold_recipient::ThresholdRecipient;

#[derive(Debug, Default)]
struct RecipientPlugin {
    recipients: Vec<ThresholdRecipient>,
}

struct CallbacksAdapter<C: age_plugin::Callbacks<recipient::Error>>(C);

#[derive(Clone)]
struct CallbacksStub;
impl age::Callbacks for CallbacksStub {
    // FIXME
    fn display_message(&self, _: &str) {}
    fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
        None
    }
    fn request_public_string(&self, _: &str) -> Option<std::string::String> {
        None
    }
    fn request_passphrase(&self, _: &str) -> Option<Secret<std::string::String>> {
        None
    }
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
        callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        Ok(Ok(self
            .recipients
            .iter()
            .map(|r| {
                file_keys
                    .iter()
                    .map(|fk| {
                        let shares = crypto::share_secret(fk, r.t.into(), r.recipients.len());
                        let enc_shares = shares
                            .iter()
                            .zip(r.recipients.iter())
                            .map(|(s, r)| {
                                r.to_recipient(CallbacksStub {})
                                    .unwrap() // FIXME: error handling
                                    .wrap_file_key(&s.file_key)
                                    .unwrap()
                            })
                            .collect::<Vec<_>>();
                        Stanza {
                            tag: "threshold".into(),
                            args: vec![],
                            body: rlp::encode(
                                &enc_shares
                                    .iter()
                                    .flatten()
                                    .flat_map(|s| s.body.clone()) // FIXME: some serialization?
                                    .collect::<Vec<_>>(),
                            )
                            .to_vec(),
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

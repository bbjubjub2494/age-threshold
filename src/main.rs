use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::{arg, command};
use std::collections::HashMap;
use std::io;
use std::string::String;
use std::sync::mpsc::{Receiver, Sender};

use age_core::secrecy::Secret;
use age_plugin_threshold::crypto;
use age_plugin_threshold::threshold_recipient::ThresholdRecipient;
use rlp::{RlpDecodable, RlpEncodable};

#[derive(Debug, Default)]
struct RecipientPlugin {
    recipients: Vec<ThresholdRecipient>,
}

pub enum CallbacksMethod {
    DisplayMessage(String),
    Confirm(String, String, Option<String>, Sender<Option<bool>>),
    RequestPublicString(String, Sender<Option<String>>),
    RequestPassphrase(String, Sender<Option<Secret<String>>>),
}

// horrific hack to wrap age_plugin::Callbacks into age::Callbacks.
// the latter requires a Send + Sync + 'static trait object, which is not possible to implement using the former.
// instead, we keep the age::Callback in one thread and do RPC from another.
static senders: std::sync::Mutex<Option<(Sender<CallbacksMethod>, Receiver<CallbacksMethod>)>> =
    std::sync::Mutex::new(None);

#[derive(Copy, Clone)]
struct CallbacksAdapter {}

impl CallbacksAdapter {
    fn new() -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        senders.lock().unwrap().replace((sender, receiver));
        Self {}
    }

    fn interact(&self, callbacks: &mut impl Callbacks<recipient::Error>) {
        let (_, receiver) = senders.lock().unwrap().take().unwrap();
        for method in receiver.iter() {
            match method {
                CallbacksMethod::DisplayMessage(msg) => match callbacks.message(&msg) {
                    Ok(_) => (),
                    Err(e) => eprintln!("Error: {:?}", e),
                },
                CallbacksMethod::Confirm(message, yes_string, no_string, result) => {
                    match callbacks.confirm(&message, &yes_string, no_string.as_deref()) {
                        Ok(Ok(r)) => result.send(Some(r)),
                        e => {
                            eprintln!("Error: {:?}", e);
                            result.send(None)
                        }
                    };
                }
                CallbacksMethod::RequestPublicString(message, result) => {
                    match callbacks.request_public(&message) {
                        Ok(Ok(r)) => result.send(Some(r)),
                        (e) => {
                            eprintln!("Error: {:?}", e);
                            result.send(None)
                        }
                    };
                }
                CallbacksMethod::RequestPassphrase(message, result) => {
                    match callbacks.request_secret(&message) {
                        Ok(Ok(r)) => result.send(Some(r)),
                        (e) => {
                            eprintln!("Error: {:?}", e);
                            result.send(None)
                        }
                    };
                }
            }
        }
    }

    fn reset(&self) {
        // drop the sender so the receiver stops iterating
        *senders.lock().unwrap() = None;
    }
}

impl age::Callbacks for CallbacksAdapter {
    fn display_message(&self, msg: &str) {
        let (sender, _) = senders.lock().unwrap().take().unwrap();
        sender
            .send(CallbacksMethod::DisplayMessage(msg.into()))
            .unwrap();
    }
    fn confirm(&self, message: &str, yes_string: &str, no_string: Option<&str>) -> Option<bool> {
        let (sender, _) = senders.lock().unwrap().take().unwrap();
        let (result, receiver) = std::sync::mpsc::channel();
        sender
            .send(CallbacksMethod::Confirm(
                message.into(),
                yes_string.into(),
                no_string.map(|r| r.into()),
                result,
            ))
            .unwrap();
        receiver.recv().unwrap()
    }
    fn request_public_string(&self, msg: &str) -> Option<std::string::String> {
        let (sender, _) = senders.lock().unwrap().take().unwrap();
        let (result, receiver) = std::sync::mpsc::channel();
        sender
            .send(CallbacksMethod::RequestPublicString(msg.into(), result))
            .unwrap();
        receiver.recv().unwrap()
    }
    fn request_passphrase(&self, msg: &str) -> Option<Secret<std::string::String>> {
        let (sender, _) = senders.lock().unwrap().take().unwrap();
        let (result, receiver) = std::sync::mpsc::channel();
        sender
            .send(CallbacksMethod::RequestPassphrase(msg.into(), result))
            .unwrap();
        receiver.recv().unwrap()
    }
}

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
struct EncShare {
    index: u8,
    //data: [u8; FILE_KEY_BYTES],
    stanzas: Vec<Stanza>,
}

#[derive(Debug, PartialEq, RlpEncodable, RlpDecodable)]
struct StanzaBody {
    recipient: ThresholdRecipient,
    enc_shares: Vec<EncShare>,
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
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        Ok(Ok(self
            .recipients
            .iter()
            .map(|r| {
                file_keys
                    .iter()
                    .map(|fk| {
                        let shares = crypto::share_secret(fk, r.t.into(), r.recipients.len());
                        let adapted_callbacks = CallbacksAdapter::new();
                        let recipients = r.recipients.clone();
                        let enc_shares = {
                            let thread = std::thread::spawn(move || {
                                let r = shares
                                    .iter()
                                    .zip(recipients.iter())
                                    .map(|(s, r)| EncShare {
                                        index: s.index,
                                        stanzas: r
                                            .to_recipient(adapted_callbacks)
                                            .unwrap() // FIXME: error handling
                                            .wrap_file_key(&s.file_key)
                                            .unwrap(),
                                    })
                                    .collect::<Vec<_>>();
                                adapted_callbacks.reset();
                                r
                            });
                            adapted_callbacks.interact(&mut callbacks);
                            thread.join().unwrap()
                        };
                        Stanza {
                            tag: "threshold".into(),
                            args: vec![],
                            body: rlp::encode(&StanzaBody {
                                recipient: r.clone(),
                                enc_shares: enc_shares,
                            })
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
        plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), identity::Error> {
        match plugin_name {
            "threshold" => Ok(()),
            _ => todo!("digest secret keys"),
        }
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

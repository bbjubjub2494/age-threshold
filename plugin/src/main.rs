use age_core::format::{FileKey, Stanza};

use age::Identity;
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use clap::{arg, command, Command};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::str::FromStr;
use std::string::String;
use std::sync::mpsc::{Receiver, Sender};

use age_core::secrecy::Secret;
use age_plugin_threshold::crypto::{self, SecretShare};
use rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable, RlpStream};

use age_plugin_threshold::types::GenericIdentity;
use age_plugin_threshold::types::GenericRecipient;
use age_plugin_threshold::types::ThresholdIdentity;
use age_plugin_threshold::types::ThresholdRecipient;

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
                        e => {
                            eprintln!("Error: {:?}", e);
                            result.send(None)
                        }
                    };
                }
                CallbacksMethod::RequestPassphrase(message, result) => {
                    match callbacks.request_secret(&message) {
                        Ok(Ok(r)) => result.send(Some(r)),
                        e => {
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
    stanzas: Vec<EncodableStanza>,
}

#[derive(Debug, PartialEq, Clone)]
struct EncodableStanza {
    tag: String,
    args: Vec<String>,
    body: Vec<u8>,
}

impl EncodableStanza {
    fn from(s: &Stanza) -> Self {
        Self {
            tag: s.tag.clone(),
            args: s.args.clone(),
            body: s.body.clone(),
        }
    }

    fn into(&self) -> Stanza {
        Stanza {
            tag: self.tag.clone(),
            args: self.args.clone(),
            body: self.body.clone(),
        }
    }
}

impl Encodable for EncodableStanza {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.tag);
        s.begin_list(self.args.len());
        for a in &self.args {
            s.append(a);
        }
        s.append(&self.body);
    }
}

impl Decodable for EncodableStanza {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            tag: rlp.at(0)?.as_val()?,
            args: rlp.at(1)?.as_list()?,
            body: rlp.at(2)?.as_val()?,
        })
    }
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
        self.recipients.push(rlp::decode(bytes).unwrap());
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
                                            .unwrap()
                                            .iter()
                                            .map(|s| EncodableStanza::from(s))
                                            .collect(),
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
struct IdentityPlugin {
    identities: Vec<GenericIdentity>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        _index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != "threshold" {
            panic!("not age-plugin-threshold");
        }
        let identity: ThresholdIdentity = rlp::decode(bytes).unwrap();
        self.identities.push(identity.inner_identity);
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        file_keys: Vec<Vec<Stanza>>,
        callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut r = HashMap::new();
        for (i, efk) in file_keys.iter().enumerate() {
            for stanza in efk {
                if stanza.tag != "threshold" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "not a threshold stanza",
                    ));
                }
                let body = rlp::decode::<StanzaBody>(&stanza.body).unwrap();
                let mut shares = vec![];
                for (j, s) in body.enc_shares.iter().enumerate() {
                    for s in &s.stanzas {
                        dbg!(&s);
                        for i in &self.identities {
                            dbg!(&i);
                            match (&i.plugin, s.tag.as_str()) {
                                (None, "X25519") => {
                                    // built-in identity
                                    let i =
                                        age::x25519::Identity::from_str(&i.to_bech32()).unwrap();
                                    match i.unwrap_stanza(&s.into()) {
                                        Some(Ok(r)) => {
                                            shares.push(SecretShare {
                                                index: j.try_into().unwrap(),
                                                file_key: r,
                                            });
                                            break;
                                        }
                                        Some(Err(e)) => panic!("{}", e),
                                        None => (),
                                    }
                                }
                                (Some(plugin), tag) if plugin == tag => {
                                    todo!();
                                }
                                _ => {
                                    // ignore
                                }
                            }
                        }
                    }
                }
                dbg!(&shares);
                let fk = crypto::reconstruct_secret(&shares[..]);
                r.insert(i, Ok(fk));
                break; // todo: handle multiple stanzas per file
            }
        }
        Ok(r)
    }
}

fn read_file(path: &str) -> io::Result<String> {
    let file = File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line2 = line?;
        let line3 = line2.trim();
        if !line3.starts_with("#") {
            return Ok(line3.into());
        }
    }
    panic!("no data found");
}

fn main() -> io::Result<()> {
    let cmd = command!()
        .arg(arg!(--"age-plugin" <state_machine> "run the given age plugin state machine"))
        .subcommand(
            Command::new("wrap")
                .long_flag("warp")
                .about("wrap an identity")
                .arg(arg!(<identity> "identity to wrap")),
        )
        .subcommand(
            Command::new("build-recipient")
                .about("prepare a threshold recipient")
                .arg(arg!(<recipients> "recipients"))
                .arg(arg!(-t --threshold <threshold> "threshold")),
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

    match cmd.subcommand() {
        Some(("wrap", subcmd)) => {
            let path = subcmd.get_one::<String>("identity").unwrap();
            let identity = read_file(path).unwrap();
            let inner_identity = GenericIdentity::from_bech32(&identity).unwrap();
            println!("# wraps {}", inner_identity.to_bech32());
            let identity = ThresholdIdentity { inner_identity };
            println!("{}", identity.to_bech32());
        }
        Some(("build-recipient", subcmd)) => {
            let recipients = subcmd.get_many::<String>("recipients").unwrap();
            let t = 1u16; // TODO
            let recipient = ThresholdRecipient {
                t,
                recipients: recipients
                    .map(|r| GenericRecipient::from_bech32(r.as_str()).unwrap())
                    .collect(),
            };
            println!("{}", recipient.to_bech32());
        }
        _ => {
            eprintln!("No subcommand given");
            std::process::exit(1);
        }
    }

    Ok(())
}

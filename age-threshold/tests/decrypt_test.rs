use age::secrecy::ExposeSecret;
use std::io;

#[test]
fn decrypt_sample() -> io::Result<()> {
    let msg = testdata::Data::get("2outof3/message").unwrap();
    let enc_msg = testdata::Data::get("2outof3/message.age").unwrap();
    let key1 = testdata::Data::get("2outof3/key1").unwrap();
    let key2 = testdata::Data::get("2outof3/key2").unwrap();

    let err = age_threshold::decrypt(&[], &mut io::Cursor::new(&enc_msg.data), &mut io::sink());
    assert!(err.is_err());

    let age::IdentityFileEntry::Native(ref id) =
        age::IdentityFile::from_buffer(io::Cursor::new(&key1.data))?.into_identities()[0]
    else {
        unreachable!()
    };
    let id1 =
        age_threshold::types::AgeIdentity::from_bech32(id.to_string().expose_secret()).unwrap();
    let age::IdentityFileEntry::Native(ref id) =
        age::IdentityFile::from_buffer(io::Cursor::new(&key2.data))?.into_identities()[0]
    else {
        unreachable!()
    };
    let id2 =
        age_threshold::types::AgeIdentity::from_bech32(id.to_string().expose_secret()).unwrap();
    let mut buf = io::Cursor::new(vec![]);
    age_threshold::decrypt(&[id1, id2], &mut io::Cursor::new(&enc_msg.data), &mut buf)?;
    assert_eq!(&buf.get_ref()[..], &msg.data[..]);

    Ok(())
}

#[test]
fn decrypt_sample_pq() -> io::Result<()> {
    if let Err(age::EncryptError::MissingPlugin { .. }) =
        age::plugin::RecipientPluginV1::new("simplepq", &[], &[], age::cli_common::UiCallbacks)
    {
        eprintln!("cannot run test: age-plugin-simplepq is not installed!");
        return Ok(());
    }
    let msg = testdata::Data::get("2outof3_pq/message").unwrap();
    let enc_msg = testdata::Data::get("2outof3_pq/message.age").unwrap();
    let key1 = testdata::Data::get("2outof3_pq/key1").unwrap();
    let key2 = testdata::Data::get("2outof3_pq/key2").unwrap();

    let err = age_threshold::decrypt(&[], &mut io::Cursor::new(&enc_msg.data), &mut io::sink());
    assert!(err.is_err());

    let age::IdentityFileEntry::Plugin(ref id) =
        age::IdentityFile::from_buffer(io::Cursor::new(&key1.data))?.into_identities()[0]
    else {
        unreachable!()
    };
    let id1 = age_threshold::types::AgeIdentity::Plugin(id.clone());
    let age::IdentityFileEntry::Plugin(ref id) =
        age::IdentityFile::from_buffer(io::Cursor::new(&key2.data))?.into_identities()[0]
    else {
        unreachable!()
    };
    let id2 = age_threshold::types::AgeIdentity::Plugin(id.clone());
    let mut buf = io::Cursor::new(vec![]);
    age_threshold::decrypt(&[id1, id2], &mut io::Cursor::new(&enc_msg.data), &mut buf)?;
    assert_eq!(&buf.get_ref()[..], &msg.data[..]);

    Ok(())
}

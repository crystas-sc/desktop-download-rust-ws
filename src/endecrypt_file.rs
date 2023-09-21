use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream,  NewAead},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{ File},
    io::{Read, Write},
};

fn main() -> Result<(), anyhow::Error> {
    let mut large_file_key = [0u8; 32];
    let mut large_file_nonce = [0u8; 19];
    OsRng.fill_bytes(&mut large_file_key);
    OsRng.fill_bytes(&mut large_file_nonce);

    let mykey = String::from("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    let mynounce = String::from("00010203040506070800001020304050607080");
    let hexkey = hex::decode(mykey.as_bytes()).expect("Decoding failed");
    let hexnounce = hex::decode(mynounce.as_bytes()).expect("Decoding failed");
    large_file_key.copy_from_slice(&hexkey[..32]);
    large_file_nonce.copy_from_slice(&hexnounce[..19]);
    // large_file_nonce.copy_from_slice(&hex::decode(mynounce).expect("Decoding failed")[..19]);

    println!("Encrypting 2048.bin to 2048.encrypted");
    encrypt_large_file(
        "thebook.pdf",
        "2048.encrypted",
        &large_file_key,
        &large_file_nonce,
    )?;

    println!("Decrypting 2048.encrypted to 2048.decrypted");
    decrypt_large_file(
        "2048.encrypted",
        "2048.decrypted",
        &large_file_key,
        &large_file_nonce,
    )?;

   

    Ok(())
}

pub fn decrypt_file(encrypted_file_path: &str)-> Result<(), anyhow::Error>{
    let mut large_file_key = [0u8; 32];
    let mut large_file_nonce = [0u8; 19];
    OsRng.fill_bytes(&mut large_file_key);
    OsRng.fill_bytes(&mut large_file_nonce);

    let mykey = String::from("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F");
    let mynounce = String::from("00010203040506070800001020304050607080");
    let hexkey = hex::decode(mykey.as_bytes()).expect("Decoding failed");
    let hexnounce = hex::decode(mynounce.as_bytes()).expect("Decoding failed");
    large_file_key.copy_from_slice(&hexkey[..32]);
    large_file_nonce.copy_from_slice(&hexnounce[..19]);

    decrypt_large_file(
        encrypted_file_path,
        &encrypted_file_path.replace(".encrypted",""),
        &large_file_key,
        &large_file_nonce,
    )?;
    Ok(())
}

fn encrypt_large_file(
    source_file_path: &str,
    dist_file_path: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut dist_file = File::create(dist_file_path)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

fn decrypt_large_file(
    encrypted_file_path: &str,
    dist: &str,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut dist_file = File::create(dist)?;

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
            break;
        }
    }

    Ok(())
}

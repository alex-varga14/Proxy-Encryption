use recrypt::prelude::*;
use recrypt::api::Plaintext;
use pad::PadStr;
use std::env;

// Recrypt is a pure-Rust library that implements a set of cryptographic primitives for 
// building a multi-hop proxy Re-encryption scheme, known as Transform Encryption.

fn main() {
    fn unsize<T>(x: &[T]) -> &[T] { x }

    // new Recrypt
    let  recrypt = Recrypt::new();

    let mut mystr= "Hello";
    let args: Vec<String>  = env::args().collect();

    if args.len() > 1
    {  
        mystr = &args[1];
    }

    let x = Plaintext::new_from_slice(mystr.pad_to_width_with_char(384,' ').as_bytes());
    let pt = x.unwrap();

    //generate signing keypair
    let signing_keypair= recrypt.generate_ed25519_key_pair();

    // create "Alice's" keypair
    let (initial_priv_key, initial_pub_key) = recrypt.generate_key_pair().unwrap();

    // encrypt message with Alice's pub key.
    let encrypted_val = recrypt.encrypt(&pt, &initial_pub_key, &signing_keypair).unwrap();

    // create "Bob's" keypair
    let (target_priv_key, target_pub_key) = recrypt.generate_key_pair().unwrap();

    // Alice generates transform key for the group
    let initial_to_target_transform_key = recrypt.generate_transform_key(
        &initial_priv_key,
        &target_pub_key,
        &signing_keypair
        ).unwrap();

    // transform to convert to ciphertext
    let transformed_val = recrypt.transform(
        encrypted_val,
        initial_to_target_transform_key,
        &signing_keypair
        ).unwrap();

    // decrypt the transform ciphertext using Bob's priv key
    let decrypted_val = recrypt.decrypt(transformed_val, &target_priv_key).unwrap();

    println!("\nInput string:\t{} ",mystr);
    println!("\nSigning key:\t{} ",hex::encode(unsize(signing_keypair.bytes())));
    println!("\nInitial Private key:\t{} ",hex::encode(unsize(initial_priv_key.bytes())));

    let (x,y)=initial_pub_key.bytes_x_y();
    println!("\nInitial Public key:\t{},{} ",hex::encode(unsize(x)),hex::encode(unsize(y)));
    println!("\nTarget Private key:\t{} ",hex::encode(unsize(target_priv_key.bytes())));

    let (x,y)=target_pub_key.bytes_x_y();
    println!("\nTarget Public key:\t{},{} ",hex::encode(unsize(x)),hex::encode(unsize(y)));
    println!("\nDecrypted:\t{} ",String::from_utf8_lossy(decrypted_val.bytes()));
}
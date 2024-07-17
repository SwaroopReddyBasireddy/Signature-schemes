use bls_signatures::{
    schemes::bls12_381::G2Scheme as SigScheme,
    sig::{Scheme, SignatureScheme}
 };


fn main() {
let (private, public) = SigScheme::keypair(&mut rand::thread_rng());
 let msg = b"hello";
 let sig = SigScheme::sign(&private, &msg[..]).unwrap();
 SigScheme::verify(&public, &msg[..], &sig).expect("signature should be verified");

 println!("{:?}", msg);
 println!("{:?}", sig);
 println!("Private key = {private}, Public Key = {public}");
}    

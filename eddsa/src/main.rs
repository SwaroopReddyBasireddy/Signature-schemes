
extern crate ed25519_dalek;
extern crate hex;
extern crate rand;
extern crate alloc;
// extern crate merlin;

use ed25519_dalek::*;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;

use alloc::vec::Vec;

// use core::convert::TryFrom;
// use core::iter::once;
// use merlin::Transcript;

 use curve25519_dalek::constants;
 use curve25519_dalek::edwards::EdwardsPoint;
 use curve25519_dalek::scalar::Scalar;
 use curve25519_dalek::traits::IsIdentity;
 use curve25519_dalek::traits::VartimeMultiscalarMul;

pub use curve25519_dalek::digest::Digest;

 use sha2::Sha512;

//use rand_core::OsRng;
use std::env;
use rand::rngs::OsRng;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;


//use rayon::prelude::*;
fn main() {
    let num_messages = 100;
   let mut str1 ="This is a test of the Ed25519 signature in Rust.";
   let args: Vec<_> = env::args().collect();
   let mut rng  = ChaCha8Rng::seed_from_u64(12);
   
   let messages: Vec<Vec<u8>> = (0..num_messages)
          .map(|_| (0..64).map(|_| rng.gen()).collect())
          .collect();
   //let msgs: Vec<&[u8]> = messages.iter().map(|msg| &msg).collect();
   let a: Vec<u8> =  (0..64).map(|_| rng.gen()).collect();
   let b = &a;
   //println!("a = {:?}", a);
   //println!("b = {:?}", b);
   let c: Vec<u8> =  (0..64).map(|_| rng.gen()).collect();
   let d: &[u8] = &c;
   let mut msgs: Vec<&[u8]> = Vec::new();
   println!("messages.len() = {}", messages.len());
  
   for i in 0..num_messages {
        msgs.push(&messages[i]);
        println!("\n******* {} th message ******", i);
        println!("Message = {:?}", messages[i]);
        println!("msg = {:?}", msgs[i]);
    }
   //println!("c = {:?}", c);
//   println!("d = {:?}", d);
//    let random_bytes: Vec<[u8;32]> = (0..100).map(|_| rand::thread_rng().gen::<[u8; 32]>()).collect();
//     println!("{:?}", random_bytes);
//    let messages: Vec<&[u8;32]> = random_bytes.iter()
//                   .map(|msg| msg).collect();
}
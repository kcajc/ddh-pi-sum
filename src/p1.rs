use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use libpaillier::{Ciphertext, EncryptionKey, Nonce};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashSet;

pub struct P1 {
    v: Vec<String>,
    k_1: Scalar,
}

// libpaillier 0.6.0 has a bug of refusing to encrypt zero lol
fn encrypt_zero(pk: &EncryptionKey) -> Ciphertext {
    let r = Nonce::random(pk.n());
    r.modpow(pk.n(), pk.nn())
}

impl P1 {
    pub fn new(items: Vec<&str>) -> Self {
        Self {
            v: items.iter().map(|s| s.to_string()).collect(),
            k_1: Scalar::random(&mut thread_rng()),
        }
    }

    pub fn round_1(&self) -> Vec<RistrettoPoint> {
        let mut points = self
            .v
            .iter()
            .map(|v_i| self.k_1 * RistrettoPoint::hash_from_bytes::<sha2::Sha512>(&v_i.as_bytes()))
            .collect::<Vec<RistrettoPoint>>();
        points.shuffle(&mut thread_rng());
        points
    }

    pub fn round_3(
        &self,
        pk: &EncryptionKey,
        msg_2: (Vec<RistrettoPoint>, Vec<(RistrettoPoint, Ciphertext)>),
    ) -> Ciphertext {
        let (z, p2_points_and_vals) = msg_2;
        let z_set: HashSet<CompressedRistretto> =
            HashSet::from_iter(z.iter().map(|&h| h.compress()));
        let encrypted_sum = p2_points_and_vals
            .into_iter()
            .filter_map(|(point, encrypted_val)| {
                let z_lookup = (self.k_1 * point).compress();
                z_set.contains(&z_lookup).then_some(encrypted_val)
            })
            .reduce(|acc, val| pk.add(&acc, &val).unwrap());

        // ARefresh
        let encrypted_zero = encrypt_zero(&pk);
        match encrypted_sum {
            Some(encrypted_sum) => {
                pk.add(
                    &encrypted_sum,
                    &encrypted_zero, // Refresh encryption
                )
                .unwrap()
            }
            None => encrypted_zero,
        }
    }
}

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use fast_paillier::backend::Integer;
use fast_paillier::{Ciphertext, EncryptionKey};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::collections::HashSet;

pub struct P1 {
    v: Vec<String>,
    k_1: Scalar,
}

impl P1 {
    pub fn new(items: Vec<String>) -> Self {
        Self {
            v: items,
            k_1: Scalar::random(&mut OsRng),
        }
    }

    pub fn round_1(&self) -> Vec<RistrettoPoint> {
        let mut points = self
            .v
            .iter()
            .map(|v_i| self.k_1 * RistrettoPoint::hash_from_bytes::<sha2::Sha512>(v_i.as_bytes()))
            .collect::<Vec<RistrettoPoint>>();
        points.shuffle(&mut OsRng);
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
        let mut intersection_size = 0u32;
        let encrypted_sum = p2_points_and_vals
            .into_iter()
            .filter_map(|(point, encrypted_val)| {
                let z_lookup = (self.k_1 * point).compress();
                z_set.contains(&z_lookup).then_some(encrypted_val)
            })
            .inspect(|_| intersection_size += 1)
            .reduce(|acc, val| pk.oadd(&acc, &val).unwrap());
        println!("Intersection size: {}", intersection_size);

        let (encrypted_zero, _) = pk
            .encrypt_with_random(&mut OsRng, &Integer::zero())
            .unwrap();
        match encrypted_sum {
            Some(encrypted_sum) => pk.oadd(&encrypted_sum, &encrypted_zero).unwrap(), // ARefresh
            None => encrypted_zero, // Empty intersection
        }
    }
}

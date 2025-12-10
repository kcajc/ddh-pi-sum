use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use fast_paillier::backend::Integer;
use fast_paillier::{Ciphertext, DecryptionKey, EncryptionKey};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::thread_rng;

pub struct P2 {
    w: Vec<(String, u32)>,
    k_2: Scalar,
    sk: DecryptionKey,
}

impl P2 {
    pub fn new(data: Vec<(String, u32)>) -> Self {
        let sk = DecryptionKey::generate(&mut OsRng).unwrap();
        Self {
            w: data,
            k_2: Scalar::random(&mut thread_rng()),
            sk,
        }
    }

    pub fn pk(&self) -> &EncryptionKey {
        self.sk.encryption_key()
    }

    pub fn round_2(
        &self,
        msg_1: Vec<RistrettoPoint>,
    ) -> (Vec<RistrettoPoint>, Vec<(RistrettoPoint, Ciphertext)>) {
        let mut z = msg_1
            .iter()
            .map(|p| p * self.k_2)
            .collect::<Vec<RistrettoPoint>>();
        z.shuffle(&mut OsRng);

        let mut p2_points_and_vals = self
            .w
            .iter()
            .map(|(w_j, t_j)| {
                let blinded_point =
                    self.k_2 * RistrettoPoint::hash_from_bytes::<sha2::Sha512>(w_j.as_bytes());
                let (encrypted_val, _) = self
                    .sk
                    .encrypt_with_random(&mut OsRng, &Integer::from(*t_j))
                    .unwrap();
                (blinded_point, encrypted_val)
            })
            .collect::<Vec<(RistrettoPoint, Ciphertext)>>();

        p2_points_and_vals.shuffle(&mut OsRng);

        (z, p2_points_and_vals)
    }

    pub fn output(&self, msg_3: &Ciphertext) {
        let sum = self.sk.decrypt(msg_3).unwrap();
        println!("{}", sum);
    }
}

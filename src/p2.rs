use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use libpaillier::{unknown_order::BigNumber, *};
use rand::seq::SliceRandom;
use rand::thread_rng;

pub struct P2 {
    w: Vec<(String, u32)>,
    k_2: Scalar,
    sk: DecryptionKey,
    pub pk: EncryptionKey,
}

impl P2 {
    pub fn new(data: Vec<(&str, u32)>) -> Self {
        let sk = DecryptionKey::random().unwrap();
        let pk = EncryptionKey::from(&sk);
        Self {
            w: data.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            k_2: Scalar::random(&mut thread_rng()),
            sk,
            pk,
        }
    }

    pub fn round_2(
        &self,
        msg_1: Vec<RistrettoPoint>,
    ) -> (Vec<RistrettoPoint>, Vec<(RistrettoPoint, Ciphertext)>) {
        let mut rng = thread_rng();

        let mut z = msg_1
            .iter()
            .map(|p| p * self.k_2)
            .collect::<Vec<RistrettoPoint>>();
        z.shuffle(&mut rng);

        let mut p2_points_and_vals = self
            .w
            .iter()
            .map(|(w_j, t_j)| {
                let blinded_point =
                    self.k_2 * RistrettoPoint::hash_from_bytes::<sha2::Sha512>(&w_j.as_bytes());
                let (encrypted_val, _) = self
                    .pk
                    .encrypt(&BigNumber::from(*t_j).to_bytes(), None)
                    .unwrap();
                (blinded_point, encrypted_val)
            })
            .collect::<Vec<(RistrettoPoint, Ciphertext)>>();

        p2_points_and_vals.shuffle(&mut rng);

        (z, p2_points_and_vals)
    }

    pub fn output(&self, msg_3: &Ciphertext) {
        let sum = BigNumber::from_slice(self.sk.decrypt(msg_3).unwrap());
        println!("{}", sum);
    }
}

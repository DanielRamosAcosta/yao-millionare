use num::{BigUint, ToPrimitive};
use num_primes::Generator;
use rsa::{PublicKeyParts, RsaPrivateKey};

pub struct Provider {
    key: RsaPrivateKey,
    money: u8,
}

impl Provider {
    pub fn new(key: RsaPrivateKey, money: u8) -> Provider {
        Provider { key, money }
    }

    pub fn get_batch_z(&self, ciphertext: BigUint) -> (BigUint, Vec<BigUint>) {
        let d_bytes = self.key.d().to_bytes_be();
        let d = BigUint::from_bytes_be(&d_bytes);
        let n_bytes = self.key.n().to_bytes_be();
        let n = BigUint::from_bytes_be(&n_bytes);
        let range = 0..21;

        let y_u = range
            .map(|u| {
                // pow(enc_score + i, d, N);
                let foo = ciphertext.clone() + u.to_u32().unwrap();

                return foo.modpow(&d, &n);
            })
            .enumerate()
            .map(|(i, z)| {
                if i >= self.money.to_usize().unwrap() {
                    z + 1u8
                } else {
                    z
                }
            })
            .collect::<Vec<BigUint>>();

        let prime_bytes = Generator::new_prime((48).to_usize().unwrap()).to_bytes_be();
        let prime = BigUint::from_bytes_be(&prime_bytes);

        let z_u = y_u.iter().map(|x| x % &prime).collect::<Vec<BigUint>>();

        return (prime, z_u);
    }
}

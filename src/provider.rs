use num_primes::Generator;
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey};
use std::ops::Range;

pub struct Provider {
    key: RsaPrivateKey,
    money: u8,
    money_max: u16,
}

impl Provider {
    pub fn new(key: RsaPrivateKey, money: u8, money_max: u16) -> Provider {
        Provider {
            key,
            money,
            money_max,
        }
    }

    pub fn get_batch_z(&self, ciphertext: BigUint) -> (BigUint, Vec<BigUint>) {
        let range: Range<u16> = 0..(self.money_max + 1);

        let y_u = range
            .map(|u| &ciphertext + BigUint::from(u))
            .map(|r| r.modpow(&self.key.d(), &self.key.n()))
            .enumerate()
            .map(|(i, z)| {
                if i >= usize::from(self.money) {
                    z + 1u8
                } else {
                    z
                }
            })
            .collect::<Vec<BigUint>>();

        let prime = Provider::generate_prime(48);

        let z_u = y_u.iter().map(|x| x % &prime).collect::<Vec<BigUint>>();

        return (prime, z_u);
    }

    fn generate_prime(n: usize) -> BigUint {
        let prime_bytes = Generator::new_prime(n).to_bytes_be();
        let prime = BigUint::from_bytes_be(&prime_bytes);
        return prime;
    }
}

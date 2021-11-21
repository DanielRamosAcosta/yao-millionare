use rand::distributions::Uniform;
use rand::Rng;
use rsa::{BigUint, PublicKeyParts, RsaPublicKey};
use std::{error::Error, fmt};

#[derive(Debug)]
pub struct NumberListNotMatchingIndex;

impl Error for NumberListNotMatchingIndex {}

impl fmt::Display for NumberListNotMatchingIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Could not complete the protocol, z_u does not match the given index"
        )
    }
}

pub struct Answerer {
    money: u8,
    x: BigUint,
}

impl Answerer {
    pub fn new(money: u8) -> Answerer {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);

        let components: Vec<u8> = (0..256).map(|_| rng.sample(&range)).collect();

        let x = BigUint::from_bytes_be(&components);

        Answerer { money, x }
    }

    pub fn get_ciphertext(&self, peer_public_key: RsaPublicKey) -> BigUint {
        let n = peer_public_key.n();
        let e = peer_public_key.e();

        let cipher = self.x.modpow(e, n);

        return cipher - self.money;
    }

    pub fn peer_is_greater(
        &self,
        prime: BigUint,
        z_u: Vec<BigUint>,
    ) -> Result<bool, NumberListNotMatchingIndex> {
        let i = usize::from(self.money);

        let x_mod_p = &self.x % prime;

        return z_u
            .get(i)
            .map(|j_th_n| j_th_n == &x_mod_p)
            .ok_or(NumberListNotMatchingIndex {});
    }
}

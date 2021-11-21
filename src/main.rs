use crate::answerer::Answerer;
use crate::provider::Provider;
use rand::rngs::OsRng;
use rsa::pkcs1::{FromRsaPublicKey, ToRsaPublicKey};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use std::str::FromStr;

mod answerer;
mod provider;

fn read_stdin() -> String {
    let mut buffer = String::new();
    std::io::stdin()
        .read_line(&mut buffer)
        .expect("Failed reading from stdin");
    buffer
}

fn read_number_stdin() -> u8 {
    let value = read_stdin();
    value
        .trim()
        .parse::<u8>()
        .expect("I expected a number but got could not parse it")
}

fn role_bob() {
    println!("Enter your money:");
    let money = read_number_stdin();
    let bob = Answerer::new(money);

    println!("Enter Alice's public PEM");
    let alice_public_key_pem = read_stdin().replace("\\n", "\n");
    let alice_public_key = RsaPublicKey::from_pkcs1_pem(&alice_public_key_pem)
        .expect("Could not parse Alice's Public key PEM");
    println!("Give Alice this ciphertext:");
    let ciphertext = bob.get_ciphertext(alice_public_key);
    println!("{}", ciphertext);

    println!("Give me Alice's generated prime");
    let prime_str_spaces = read_stdin();
    let prime_str = prime_str_spaces.trim();
    let prime = BigUint::from_str(prime_str).expect("could not parse prime number");

    println!("Give me Alice's generated z_u");
    let z_u_str = read_stdin();
    let z_u = z_u_str
        .trim()
        .split(";")
        .map(|z_str| BigUint::from_str(z_str).expect("could not parse z_u number"))
        .collect::<Vec<BigUint>>();

    println!("Does Alice has more money?");
    let result = bob.peer_is_greater(prime, z_u).unwrap();
    println!("{}", result);
}

fn role_alice() {
    println!("Enter your money:");
    let money = read_number_stdin();
    let mut rng = OsRng::default();
    let bits = 2048;
    let key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let alice = Provider::new(key.clone(), money, 20);
    let public_key = RsaPublicKey::from(key);
    let public_key_pem = public_key
        .to_pkcs1_pem()
        .expect("could not generate public key PEM")
        .trim()
        .replace("\n", "\\n");

    println!("Give my public key to bob:");
    println!("{}", public_key_pem);
    println!("Give me Bob's ciphertext:");
    let ciphertext_str_spaces = read_stdin();
    let ciphertext_str = ciphertext_str_spaces.trim();
    let ciphertext = BigUint::from_str(ciphertext_str).expect("could not parse ciphertext");

    let (prime, z_u) = alice.get_batch_z(ciphertext);

    println!("Send the prime and z_u to Bob:");
    println!("{}", prime);
    let z_u_serialized = z_u.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    println!("{}", z_u_serialized.join(";"));
}

fn main() {
    println!("Do you want to be Alice (provider) [A] or Bob (answerer) [B]?");
    let role_without_trim = read_stdin();
    let role = role_without_trim.trim();

    match role {
        "A" => role_alice(),
        "B" => role_bob(),
        _ => {
            panic!("Unknown role {}", role)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::BigUint;

    fn generate_private_key() -> RsaPrivateKey {
        let alice_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAqAiX9a+Qpou2BA6TU63hs4Xx3Qy1IRAXpa8hpwQB1foqwYQ6\nZOR/P3jY/PhyCBdO/hBbfI15aEVS7Gpq0vqscPTIwiBwX2Q/xGS8qpWwOz+DOLlW\nR4cuQWVMxtT136sXdAGt8KgJoTSa89ZNOZl8pbLD2sq09enkRu/488VJPuoJK9Ru\n1JdjzynWHuiMgdqtf/4cA7YAYLyMWpUKL25nwnjjOHI2u7LC0C7s6fr/pqzAaXID\nxLbn0NDxPQyldOqGOjPlREFkn2/u0FIEa2rpr8GYWM/KBGYb9NBNEH0Ii/EWbIrq\nt70i+t0TOLoS3QOFmUvf6uOYKI3Pb3fQ33vvJQIDAQABAoIBAEi593NJunSq8WuO\nF2vXTWGS7py63EZkHagDRbBwxo6jSRAat99lGkIRfvD2YvxngjPqRn6BCPP9VSen\n43ZPMoVtHNsQiTJwRD0vUI0QXoc2NQg/Bz3MH1QEkRdZotVcyrjV5T/MquZPy2UP\n8rqkWNOqrKQsqefphHjDcl+nms0UbmD7QB+7bybk774qeKZ5oQeDfRBX3YSwvPwE\nKH5SeQi+gl5ksin6uSG2NjiLnx4poYPtP+MAQArP31GbuXcBXl3wOc/89pYMdK1i\n0uFpH12xyN1r+YI2zQizr0mBY5Bm0GoVWQFe2XUpClY/4G9RIOzChT+G7TRrsBnD\nB5QKhb0CgYEA89o7xwFSD6hJriy+mm6UBtlw5NkhJDJaLC8Q2GZmeNwOcZPNSNjF\nHCGhuYCqONG37tCfhxS11kB8ij9VZmQoqPDkQM0V6Z18rK7cp4awYan59ja8TeYU\nIig9negKiplxMO3SK+E77H/GELD68x+MrRy4uXa52dSqNqGgbhFFpIcCgYEAsGd3\nvVwNQ+KuKy9hQPTCXSzS8GRlyS2YxgWLygJVE9RJzHlEvhnUZccUN/G5U+XV8kf+\nnOxdD+lfh3o8d35VdZMvpCy9sVSKHfx1qIXIjvuP2j2viAMPsUJM4iPBzgxBDjxX\n6chKlbSoPTEFfMLbMdrwN9Os3TV0/07tfqEs5fMCgYBQMuwKDUMh5yUkZY7iV4/T\nmNvqSAcAUpcZhPkzUqpNAYK2k/emB7T8BYuc6NYTDdZCctakpIkRR/Atv5qkrDg7\nJ87KCSk1xhfk6zWi20dTN4YAFgxkSlFA0p9BObmNz91MTEsdJ1x/8Z4Ai1RddXjc\nzl9qj8OcArdgdFPBH2kaLQKBgFj3xhc1vub3A3p6SeV1zDUr7zMYn5FIMt3kXC1E\n4d2/Wn0KyFXMNyghsJvKiPq8Vxv7nXlNaF4nCGwOhUKK79T9p7B4dC9kgMhA1KJq\n3szmKRYbuFSzno1678W53PvriEACxR/+SUeZtqQt/iN/LwfE8RRm6K8kT96X0wXj\nif5rAoGAat7cdufmDlBF8zCPc3rh7dirdNhd68bdyADaLUR0BF+DLX4VD5gzIlqQ\n35PWrbax/f4dlD3IMjAK0i3Q/jcq+SRwKMBDDyoB8JFC3vg5RhY1m4/PQhaFBilU\nge8HIa2948MptDU79zc4KSv7y1nLH/p+WwNLliaaPUkAoNddYrE=\n-----END RSA PRIVATE KEY-----";
        let alice_key = RsaPrivateKey::from_pkcs1_pem(alice_pem).unwrap();

        return alice_key;
    }

    #[test]
    fn it_works_is_peer_is_greater() {
        let money_max = 20;
        let alice_key = generate_private_key();
        let alice = Provider::new(alice_key.clone(), 10, money_max);
        let bob = Answerer::new(15);

        let ciphertext = bob.get_ciphertext(RsaPublicKey::from(&alice_key));

        let (prime, z_u) = alice.get_batch_z(ciphertext);

        let result = bob.peer_is_greater(prime, z_u).unwrap();

        assert_eq!(result, false);
    }

    #[test]
    fn it_works_is_peer_is_equal() {
        let money_max = 20;
        let alice_key = generate_private_key();
        let alice = Provider::new(alice_key.clone(), 15, money_max);
        let bob = Answerer::new(15);

        let ciphertext = bob.get_ciphertext(RsaPublicKey::from(&alice_key));

        let (prime, z_u) = alice.get_batch_z(ciphertext);

        let result = bob.peer_is_greater(prime, z_u).unwrap();

        assert_eq!(result, false);
    }

    #[test]
    fn it_works_is_peer_is_less() {
        let money_max = 20;
        let alice_key = generate_private_key();
        let alice = Provider::new(alice_key.clone(), 15, money_max);
        let bob = Answerer::new(10);

        let ciphertext = bob.get_ciphertext(RsaPublicKey::from(&alice_key));

        let (prime, z_u) = alice.get_batch_z(ciphertext);

        let result = bob.peer_is_greater(prime, z_u).unwrap();

        assert_eq!(result, true);
    }

    #[test]
    fn it_works_on_limits() {
        let money_max = 20;
        let alice_key = generate_private_key();
        let alice = Provider::new(alice_key.clone(), 0, money_max);
        let bob = Answerer::new(20);

        let ciphertext = bob.get_ciphertext(RsaPublicKey::from(&alice_key));

        let (prime, z_u) = alice.get_batch_z(ciphertext);

        let result = bob.peer_is_greater(prime, z_u).unwrap();

        assert_eq!(result, false);
    }

    #[test]
    fn it_results_on_error_if_not_matching_index() {
        let prime = BigUint::from(17u8);
        let z_u = vec![BigUint::from(1u8)];

        let bob = Answerer::new(20);

        let message = bob.peer_is_greater(prime, z_u).err().unwrap().to_string();

        assert_eq!(
            message,
            "Could not complete the protocol, z_u does not match the given index"
        )
    }
}

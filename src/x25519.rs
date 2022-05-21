use crate::fe25519;
use crate::point;
use crate::scalar;

pub fn dh_keygen(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut sk = *seed;
    scalar::clamp(&mut sk);

    let d = scalar::get32(&sk);
    let q = point::ladder_base(&d);

    let pk = fe25519::pack(&point::compress(&q));

    (sk, pk)
}

pub fn dh_exchange(pk: &[u8; 32], sk: &[u8; 32]) -> [u8; 32] {
    let rx = fe25519::unpack(pk);
    let r = point::decompress(&rx);
    let d = scalar::get32(sk);
    let ss = point::ladder(&r, &d);
    let ss = point::compress(&ss);
    fe25519::pack(&ss)
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn dh_round_trip() {
        for _ in 0..1000 {
            let (sk_a, pk_a) = dh_keygen(&thread_rng().gen());
            let (sk_b, pk_b) = dh_keygen(&thread_rng().gen());

            let ss_a = dh_exchange(&pk_b, &sk_a);
            let ss_b = dh_exchange(&pk_a, &sk_b);
            let ss_c = dh_exchange(&pk_a, &sk_a);

            assert_eq!(ss_a, ss_b);
            assert_ne!(ss_a, ss_c);
        }
    }

    #[test]
    fn dh_interop() {
        for _ in 0..1000 {
            let (sk_a, pk_a) = dh_keygen(&thread_rng().gen());
            let (sk_b, pk_b) = dh_keygen(&thread_rng().gen());

            let ss_a = dh_exchange(&pk_b, &sk_a);

            let pk_a = orion::kex::PublicKey::from(pk_a);
            let sk_b = orion::hazardous::ecc::x25519::PrivateKey::from(sk_b);
            let ss_b = orion::hazardous::ecc::x25519::key_agreement(&sk_b, &pk_a).unwrap();

            assert_eq!(ss_b, &ss_a[..]);
        }
    }
}

use crate::fe25519;
use crate::point;
use crate::point::Point;
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
    let mut r = point::decompress(&rx);
    let d = scalar::get32(sk);
    let mut ss = Point::default();
    point::ladder(&mut ss, &mut r, &rx, &d);
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

            assert_eq!(ss_a, ss_b);
        }
    }
}

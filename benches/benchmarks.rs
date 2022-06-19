use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

use qdsa::hazmat::{Point, Scalar, G};
use qdsa::x25519::x25519;
use qdsa::{public_key, sign, verify};

fn benchmarks(c: &mut Criterion) {
    fn generate_key() -> (Point, [u8; 32]) {
        loop {
            let d = Scalar::from_bytes(&thread_rng().gen());
            let q = &G * &d;
            if let Some(rep) = q.to_elligator(thread_rng().gen()) {
                return (q, rep);
            }
        }
    }

    let (q, rep) = generate_key();
    let sk_a = thread_rng().gen();
    let pk_a = public_key(&sk_a);
    let sk_b = thread_rng().gen();
    let pk_b = public_key(&sk_b);

    c.bench_function("public_key", |b| b.iter(|| public_key(&sk_a)));

    c.bench_function("x25519", |b| b.iter(|| x25519(&sk_a, &pk_b)));

    c.bench_function("sign", |b| {
        let nonce = thread_rng().gen();
        let message = b"this is a short message";

        b.iter(|| sign(&sk_a, &nonce, message, shake128))
    });

    c.bench_function("verify", |b| {
        let nonce = thread_rng().gen();
        let message = b"this is a short message";
        let sig = sign(&sk_a, &nonce, message, shake128);

        b.iter(|| verify(&pk_a, &sig, message, shake128))
    });

    c.bench_function("elligator-encode", |b| b.iter(|| q.to_elligator(128)));

    c.bench_function("elligator-decode", |b| {
        b.iter(|| Point::from_elligator(&rep))
    });
}

fn shake128(bin: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Shake128::default();
    for data in bin {
        hasher.update(data);
    }

    let mut digest = [0u8; 64];
    let mut xof = hasher.finalize_xof();
    xof.read(&mut digest);
    digest
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);

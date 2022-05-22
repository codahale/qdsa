use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use subtle::Choice;

use qdsa::hazmat::{Point, Scalar, G};
use qdsa::{public_key, sign, verify, x25519};

fn keygen_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("keygen");

    g.bench_function("x25519-qdsa", |b| b.iter(|| public_key(&[22u8; 32])));

    g.bench_function("x25529-orion", |b| {
        let sk = orion::hazardous::ecc::x25519::PrivateKey::from([0u8; 32]);
        b.iter(|| {
            let pk: orion::kex::PublicKey =
                (&sk).try_into().expect("unable to calculate public key");
            pk.to_bytes()
        })
    });

    g.finish();
}

fn ecdh_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("ecdh");

    g.bench_function("x25519-qdsa", |b| {
        let sk_a = thread_rng().gen();
        let pk_b = public_key(&thread_rng().gen());

        b.iter(|| x25519(&sk_a, &pk_b))
    });

    g.bench_function("x25529-orion", |b| {
        let sk_a = orion::hazardous::ecc::x25519::PrivateKey::from([22u8; 32]);
        let pk_a: orion::kex::PublicKey =
            (&sk_a).try_into().expect("unable to calculate public key");
        let sk_b = orion::hazardous::ecc::x25519::PrivateKey::from([23u8; 32]);
        b.iter(|| orion::hazardous::ecc::x25519::key_agreement(&sk_b, &pk_a).unwrap())
    });

    g.finish();
}

fn sign_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("sign");

    g.bench_function("qdsa", |b| {
        let sk = thread_rng().gen();
        let pk = public_key(&sk);
        let nonce = thread_rng().gen();
        let message = b"this is a short message";

        b.iter(|| sign(&pk, &sk, &nonce, message, shake128))
    });

    g.finish();
}

fn verify_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify");

    g.bench_function("qdsa", |b| {
        let sk = thread_rng().gen();
        let pk = public_key(&sk);
        let nonce = thread_rng().gen();
        let message = b"this is a short message";
        let sig = sign(&pk, &sk, &nonce, message, shake128);

        b.iter(|| verify(&pk, &sig, message, shake128))
    });

    g.finish();
}

fn elligator_benchmarks(c: &mut Criterion) {
    let mut g = c.benchmark_group("elligator");

    fn generate_key() -> (Point, [u8; 32]) {
        loop {
            let d = Scalar::reduce(&thread_rng().gen());
            let q = &G * &d;
            if let Some(rep) = q.to_elligator(Choice::from(0)) {
                return (q, rep);
            }
        }
    }

    let (q, rep) = generate_key();

    g.bench_function("encode", |b| b.iter(|| q.to_elligator(Choice::from(0))));

    g.bench_function("decode", |b| b.iter(|| Point::from_elligator(&rep)));

    g.finish();
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

criterion_group!(
    benches,
    keygen_benchmarks,
    ecdh_benchmarks,
    sign_benchmarks,
    verify_benchmarks,
    elligator_benchmarks,
);
criterion_main!(benches);

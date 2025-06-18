use criterion::{criterion_group, criterion_main, Criterion};
use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::NonZeroU8;

fn generate_hotp_sha256(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA256,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("generate_hotp_sha256", |b| {
        b.iter(|| hotp.generate(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs()))
    });
}

fn generate_hotp_sha512(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA512,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("generate_hotp_sha512", |b| {
        b.iter(|| hotp.generate(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs()))
    });
}

fn verify_hotp_sha1_success(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA1,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("verify_hotp_sha1_success", |b| b.iter(|| hotp.verify("287082", 1, 0)));
}

fn verify_hotp_sha1_fail(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA1,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("verify_hotp_sha1_fail", |b| b.iter(|| hotp.verify("000000", 1, 0)));
}

fn verify_hotp_sha256_success(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA256,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("verify_hotp_sha256_success", |b| b.iter(|| hotp.verify("247374", 1, 0)));
}

fn verify_hotp_sha256_fail(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA256,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("verify_hotp_sha256_fail", |b| b.iter(|| hotp.verify("000000", 1, 0)));
}

fn verify_hotp_sha512_success(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA512,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("verify_hotp_sha512_success", |b| b.iter(|| hotp.verify("342147", 1, 0)));
}

fn verify_hotp_sha512_fail(c: &mut Criterion) {
    let hotp = HOTP::new(
        Algorithm::SHA512,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
    );
    c.bench_function("verify_hotp_sha512_fail", |b| b.iter(|| hotp.verify("000000", 1, 0)));
}

criterion_group!(
    benches,
    generate_hotp_sha256,
    generate_hotp_sha512,
    verify_hotp_sha1_success,
    verify_hotp_sha1_fail,
    verify_hotp_sha256_success,
    verify_hotp_sha256_fail,
    verify_hotp_sha512_success,
    verify_hotp_sha512_fail
);

criterion_main!(benches);

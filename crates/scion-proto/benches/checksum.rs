#![allow(missing_docs)]

//! Comparison between different checksum implementations.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{Fill, SeedableRng};
use rand_xorshift::XorShiftRng;
use scion_proto::packet::ChecksumDigest;

fn reference_checksum(data: &[u8]) -> u16 {
    let mut cumsum = 0u32;
    let mut i = 0usize;

    let (data, leftover) = if data.len() % 2 == 0 {
        (data, 0u8)
    } else {
        (&data[..data.len() - 1], data[data.len() - 1])
    };

    while i + 1 < data.len() {
        cumsum += ((data[i] as u32) << 8) + (data[i + 1] as u32);
        i += 2;
    }
    cumsum += (leftover as u32) << 8;

    while cumsum > 0xffff {
        cumsum = (cumsum >> 16) + (cumsum & 0xffff);
    }

    !(cumsum as u16)
}

fn bench_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("Checksum");
    let mut data = Vec::new();
    let mut rng = XorShiftRng::seed_from_u64(47);

    for length in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        let mut input_vec = vec![0u8; length];
        input_vec.try_fill(&mut rng).unwrap();
        data.push((length, input_vec));
    }

    for (length, vec) in data.iter() {
        group.bench_with_input(
            BenchmarkId::new("Reference", length),
            vec.as_slice(),
            |b, data| b.iter(|| assert_ne!(0, reference_checksum(data))),
        );
        group.bench_with_input(
            BenchmarkId::new("Unsafe", length),
            vec.as_slice(),
            |b, data| b.iter(|| assert_ne!(0, ChecksumDigest::new().add_slice(data).checksum())),
        );
    }

    group.finish()
}

criterion_group!(benches, bench_checksum);
criterion_main!(benches);

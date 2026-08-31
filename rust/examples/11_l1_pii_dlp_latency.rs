use std::{hint::black_box, time::Instant};

use patronus_ark::{
    detectors::{dlp::dlp::DlpPipeline, pii::pii::PiiPipeline},
    SecurityCategory, SecurityGateway, SecurityLevel,
};

fn measure(mut operation: impl FnMut(), samples: usize, batch_size: usize) -> (f64, f64, f64) {
    for _ in 0..100 {
        operation();
    }

    let mut micros = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        for _ in 0..batch_size {
            operation();
        }
        micros.push(started.elapsed().as_secs_f64() * 1_000_000.0 / batch_size as f64);
    }
    micros.sort_by(f64::total_cmp);
    let percentile = |fraction: f64| micros[((samples - 1) as f64 * fraction) as usize];
    (percentile(0.50), percentile(0.95), percentile(0.99))
}

fn print_latency(name: &str, latency: (f64, f64, f64)) {
    println!(
        "{name:<28} p50={:>9.3} µs  p95={:>9.3} µs  p99={:>9.3} µs",
        latency.0, latency.1, latency.2
    );
}

fn exact_size_input(size: usize, suffix: &str) -> String {
    assert!(suffix.len() <= size);
    format!("{}{}", "x".repeat(size - suffix.len()), suffix)
}

fn main() {
    let short_pii = "Personalnummer: EMP-4711; E-Mail: ada@example.com";
    let short_dlp = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature";
    let long_prefix = "Interner Bericht ohne relevante Werte. ".repeat(110);
    let long_pii = format!("{long_prefix}{short_pii}");
    let long_dlp = format!("{long_prefix}{short_dlp}");
    let large_benign = "x".repeat(100 * 1024);
    let large_pii = exact_size_input(100 * 1024, "\nPersonalnummer: EMP-4711");
    let large_dlp = exact_size_input(
        100 * 1024,
        "\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
    );

    let started = Instant::now();
    let pii = PiiPipeline::new();
    let pii_init_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let started = Instant::now();
    let dlp = DlpPipeline::new();
    let dlp_init_ms = started.elapsed().as_secs_f64() * 1_000.0;

    println!("release benchmark; 1000 short/4-KiB samples, 200 100-KiB samples");
    println!(
        "input bytes: short_pii={}, short_dlp={}, long_pii={}, long_dlp={}, large={}",
        short_pii.len(),
        short_dlp.len(),
        long_pii.len(),
        long_dlp.len(),
        large_benign.len()
    );
    println!("compile/init: PII={pii_init_ms:.3} ms, DLP={dlp_init_ms:.3} ms");

    print_latency(
        "PII detector short",
        measure(
            || {
                black_box(pii.evaluate(black_box(short_pii)));
            },
            1_000,
            100,
        ),
    );
    print_latency(
        "PII detector ~4 KiB",
        measure(
            || {
                black_box(pii.evaluate(black_box(&long_pii)));
            },
            1_000,
            20,
        ),
    );
    print_latency(
        "PII detector 100 KiB benign",
        measure(
            || {
                black_box(pii.evaluate(black_box(&large_benign)));
            },
            200,
            1,
        ),
    );
    print_latency(
        "PII detector 100 KiB match",
        measure(
            || {
                black_box(pii.evaluate(black_box(&large_pii)));
            },
            200,
            1,
        ),
    );
    print_latency(
        "DLP detector short",
        measure(
            || {
                black_box(dlp.evaluate(black_box(short_dlp)));
            },
            1_000,
            100,
        ),
    );
    print_latency(
        "DLP detector ~4 KiB",
        measure(
            || {
                black_box(dlp.evaluate(black_box(&long_dlp)));
            },
            1_000,
            20,
        ),
    );
    print_latency(
        "DLP detector 100 KiB benign",
        measure(
            || {
                black_box(dlp.evaluate(black_box(&large_benign)));
            },
            200,
            1,
        ),
    );
    print_latency(
        "DLP detector 100 KiB match",
        measure(
            || {
                black_box(dlp.evaluate(black_box(&large_dlp)));
            },
            200,
            1,
        ),
    );

    let mut gateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii, SecurityCategory::Dlp],
        SecurityLevel::L1,
        None,
        false,
    );
    gateway.warmup().expect("native L1 warmup must succeed");
    print_latency(
        "PII gateway short",
        measure(
            || {
                black_box(gateway.scan_category(SecurityCategory::Pii, black_box(short_pii)));
            },
            1_000,
            50,
        ),
    );
    print_latency(
        "DLP gateway short",
        measure(
            || {
                black_box(gateway.scan_category(SecurityCategory::Dlp, black_box(short_dlp)));
            },
            1_000,
            50,
        ),
    );
    print_latency(
        "PII gateway 100 KiB benign",
        measure(
            || {
                black_box(gateway.scan_category(SecurityCategory::Pii, black_box(&large_benign)));
            },
            200,
            1,
        ),
    );
    print_latency(
        "PII gateway 100 KiB match",
        measure(
            || {
                black_box(gateway.scan_category(SecurityCategory::Pii, black_box(&large_pii)));
            },
            200,
            1,
        ),
    );
    print_latency(
        "DLP gateway 100 KiB benign",
        measure(
            || {
                black_box(gateway.scan_category(SecurityCategory::Dlp, black_box(&large_benign)));
            },
            200,
            1,
        ),
    );
    print_latency(
        "DLP gateway 100 KiB match",
        measure(
            || {
                black_box(gateway.scan_category(SecurityCategory::Dlp, black_box(&large_dlp)));
            },
            200,
            1,
        ),
    );
}

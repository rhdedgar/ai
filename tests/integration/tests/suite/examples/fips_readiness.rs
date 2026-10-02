// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional coverage of the FIPS-readiness example and real startup logs.

use praxis_test_utils::{PraxisProcess, example_config_path, free_port, http_get};

#[test]
fn fips_readiness_example_serves_and_reports_all_prerequisites() {
    let port = free_port();
    let address = format!("127.0.0.1:{port}");
    let yaml = std::fs::read_to_string(example_config_path("fips-readiness.yaml"))
        .expect("read readiness example")
        .replace("127.0.0.1:8080", &address);
    let yaml = format!("shutdown_timeout_secs: 1\ninsecure_options:\n  allow_root: true\n{yaml}");
    let mut proxy = PraxisProcess::spawn(&yaml, &address);
    let (status, body) = http_get(&address, "/", None);
    assert_eq!((status, body.as_str()), (200, "fips readiness example"));
    assert!(proxy.terminate().success(), "example exits cleanly");
    let logs = proxy.logs();
    let startup: Vec<_> = logs
        .lines()
        .filter(|line| line.contains("installed rustls crypto provider"))
        .collect();
    assert_eq!(startup.len(), 1, "readiness is logged once: {logs}");
    let line = startup.first().expect("startup readiness line");
    for field in [
        "kernel_fips=",
        "openssl_fips_properties=",
        "crypto_policy=",
        "fips_ready=",
        "fips_required=",
    ] {
        assert!(line.contains(field), "missing {field}: {logs}");
    }
    let ready = praxis_test_utils::fips_host();
    assert!(
        line.contains(&format!("fips_ready={ready}")),
        "host and application readiness agree: {logs}"
    );
    assert_eq!(
        logs.contains("crypto readiness prerequisite failed"),
        !ready,
        "ordinary startup logs failed prerequisites: {logs}"
    );
}

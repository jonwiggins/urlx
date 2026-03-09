//! Throughput benchmarks for liburlx parsers.

#![allow(missing_docs, unused_results)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_url_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_parsing");

    group.bench_function("simple_http", |b| {
        b.iter(|| liburlx::Url::parse(black_box("http://example.com/")));
    });

    group.bench_function("https_with_path", |b| {
        b.iter(|| {
            liburlx::Url::parse(black_box("https://example.com/api/v1/users?page=1&limit=50"))
        });
    });

    group.bench_function("with_credentials", |b| {
        b.iter(|| liburlx::Url::parse(black_box("http://admin:secret@example.com:8080/path")));
    });

    group.bench_function("complex_url", |b| {
        b.iter(|| {
            liburlx::Url::parse(black_box(
                "https://user:pass@sub.example.com:8443/api/v2/resource?key=value&foo=bar#section",
            ))
        });
    });

    group.bench_function("no_scheme_default", |b| {
        b.iter(|| liburlx::Url::parse(black_box("example.com/path")));
    });

    group.finish();
}

fn bench_cookie_jar(c: &mut Criterion) {
    let mut group = c.benchmark_group("cookie_jar");

    group.bench_function("store_simple", |b| {
        b.iter(|| {
            let mut jar = liburlx::CookieJar::new();
            jar.store_cookies(
                black_box(&["session=abc123"]),
                black_box("example.com"),
                black_box("/"),
            );
        });
    });

    group.bench_function("store_with_attributes", |b| {
        b.iter(|| {
            let mut jar = liburlx::CookieJar::new();
            jar.store_cookies(
                black_box(&[
                    "session=abc123; Path=/api; Domain=example.com; Secure; HttpOnly; Max-Age=3600",
                ]),
                black_box("example.com"),
                black_box("/"),
            );
        });
    });

    group.bench_function("lookup_10_cookies", |b| {
        let mut jar = liburlx::CookieJar::new();
        for i in 0..10 {
            jar.store_cookies(&[&format!("key{i}=value{i}")], "example.com", "/");
        }
        b.iter(|| jar.cookie_header(black_box("example.com"), black_box("/api"), black_box(false)));
    });

    group.bench_function("lookup_100_cookies", |b| {
        let mut jar = liburlx::CookieJar::new();
        for i in 0..100 {
            jar.store_cookies(&[&format!("key{i}=value{i}")], "example.com", "/");
        }
        b.iter(|| jar.cookie_header(black_box("example.com"), black_box("/api"), black_box(false)));
    });

    group.finish();
}

fn bench_hsts_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("hsts_cache");

    group.bench_function("store_and_lookup", |b| {
        b.iter(|| {
            let mut cache = liburlx::HstsCache::new();
            cache.store(black_box("example.com"), black_box("max-age=31536000; includeSubDomains"));
            cache.should_upgrade(black_box("sub.example.com"))
        });
    });

    group.bench_function("lookup_miss_10_entries", |b| {
        let mut cache = liburlx::HstsCache::new();
        for i in 0..10 {
            cache.store(&format!("host{i}.com"), "max-age=31536000");
        }
        b.iter(|| cache.should_upgrade(black_box("unknown.com")));
    });

    group.bench_function("lookup_hit_subdomain", |b| {
        let mut cache = liburlx::HstsCache::new();
        cache.store("example.com", "max-age=31536000; includeSubDomains");
        b.iter(|| cache.should_upgrade(black_box("deep.sub.example.com")));
    });

    group.finish();
}

fn bench_dns_cache(c: &mut Criterion) {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let mut group = c.benchmark_group("dns_cache");

    group.bench_function("put_and_get", |b| {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        b.iter(|| {
            let mut cache = liburlx::DnsCache::new();
            cache.put(black_box("example.com"), black_box(443), vec![addr]);
            let _ = cache.get(black_box("example.com"), black_box(443)).is_some();
        });
    });

    group.bench_function("get_hit_10_entries", |b| {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let mut cache = liburlx::DnsCache::new();
        for i in 0..10 {
            cache.put(&format!("host{i}.example.com"), 443, vec![addr]);
        }
        cache.put("target.example.com", 443, vec![addr]);
        b.iter(|| cache.get(black_box("target.example.com"), black_box(443)));
    });

    group.bench_function("get_miss", |b| {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let mut cache = liburlx::DnsCache::new();
        for i in 0..10 {
            cache.put(&format!("host{i}.example.com"), 443, vec![addr]);
        }
        b.iter(|| cache.get(black_box("unknown.com"), black_box(443)));
    });

    group.finish();
}

fn bench_response_header(c: &mut Criterion) {
    use std::collections::HashMap;

    let mut group = c.benchmark_group("response_header");

    group.bench_function("lookup_lowercase", |b| {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        headers.insert("content-length".to_string(), "1234".to_string());
        headers.insert("x-request-id".to_string(), "abc-123".to_string());
        let resp =
            liburlx::Response::new(200, headers, Vec::new(), "http://example.com".to_string());
        b.iter(|| resp.header(black_box("content-type")));
    });

    group.bench_function("lookup_mixed_case", |b| {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/html".to_string());
        headers.insert("content-length".to_string(), "1234".to_string());
        let resp =
            liburlx::Response::new(200, headers, Vec::new(), "http://example.com".to_string());
        b.iter(|| resp.header(black_box("Content-Type")));
    });

    group.finish();
}

fn bench_cookie_domain_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("cookie_domain_match");

    group.bench_function("exact_match", |b| {
        let mut jar = liburlx::CookieJar::new();
        jar.store_cookies(&["key=val"], "example.com", "/");
        b.iter(|| jar.cookie_header(black_box("example.com"), black_box("/"), black_box(false)));
    });

    group.bench_function("subdomain_match", |b| {
        let mut jar = liburlx::CookieJar::new();
        jar.store_cookies(&["key=val; Domain=example.com"], "www.example.com", "/");
        b.iter(|| {
            jar.cookie_header(
                black_box("sub.deep.example.com"),
                black_box("/path"),
                black_box(false),
            )
        });
    });

    group.bench_function("no_match_1000_cookies", |b| {
        let mut jar = liburlx::CookieJar::new();
        for i in 0..1000 {
            jar.store_cookies(&[&format!("k{i}=v{i}")], &format!("host{i}.com"), "/");
        }
        b.iter(|| jar.cookie_header(black_box("other.com"), black_box("/"), black_box(false)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_url_parsing,
    bench_cookie_jar,
    bench_hsts_cache,
    bench_dns_cache,
    bench_response_header,
    bench_cookie_domain_matching,
);
criterion_main!(benches);

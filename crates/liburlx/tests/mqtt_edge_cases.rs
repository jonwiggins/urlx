//! MQTT protocol edge case tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use liburlx::protocol::mqtt::PacketType;

// --- PacketType enum ---

#[test]
fn packet_type_connect() {
    assert_eq!(PacketType::Connect as u8, 1);
}

#[test]
fn packet_type_connack() {
    assert_eq!(PacketType::Connack as u8, 2);
}

#[test]
fn packet_type_publish() {
    assert_eq!(PacketType::Publish as u8, 3);
}

#[test]
fn packet_type_puback() {
    assert_eq!(PacketType::Puback as u8, 4);
}

#[test]
fn packet_type_subscribe() {
    assert_eq!(PacketType::Subscribe as u8, 8);
}

#[test]
fn packet_type_suback() {
    assert_eq!(PacketType::Suback as u8, 9);
}

#[test]
fn packet_type_disconnect() {
    assert_eq!(PacketType::Disconnect as u8, 14);
}

// --- PacketType equality ---

#[test]
fn packet_type_equality() {
    assert_eq!(PacketType::Connect, PacketType::Connect);
    assert_ne!(PacketType::Connect, PacketType::Publish);
}

// --- PacketType Debug ---

#[test]
fn packet_type_debug() {
    let debug = format!("{:?}", PacketType::Publish);
    assert!(debug.contains("Publish"));
}

// --- PacketType Clone/Copy ---

#[test]
fn packet_type_clone() {
    let pt = PacketType::Subscribe;
    let pt2 = pt;
    assert_eq!(pt, pt2);
}

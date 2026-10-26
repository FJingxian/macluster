use macluster_protocol::identifiers::{Id128, NodeId, QueueName, validate_name};

#[test]
fn names_accept_bounded_ascii_ids_and_reject_option_looking_values() {
    assert!(NodeId::new("mini01-a").is_ok());
    assert!(QueueName::new("pool_2").is_ok());
    assert!(NodeId::new(&format!("n{}", "a".repeat(63))).is_ok());
    assert!(NodeId::new("-mini01").is_err());
    assert!(QueueName::new("has space").is_err());
    assert!(validate_name(&"n".repeat(65)).is_err());
}

#[test]
fn uuid_round_trip_is_canonical_and_version_four() {
    let id = Id128::random();
    let encoded = id.to_string();

    assert_eq!(encoded.len(), 36);
    assert_eq!(encoded.as_bytes()[14], b'4');
    assert_eq!(Id128::parse(&encoded).unwrap(), id);
    assert!(Id128::parse("not-a-uuid").is_err());
}

#[macro_export]
/// Convert any serializable object to uncompressed bytes.
macro_rules! to_uncompressed_bytes {
    ($v: expr) => {{
        let mut bytes = Vec::new();
        let result = $v.borrow().serialize_uncompressed(&mut bytes);
        if let Ok(()) = result {
            Ok(bytes)
        } else {
            Err(result.err().unwrap())
        }
    }};
}

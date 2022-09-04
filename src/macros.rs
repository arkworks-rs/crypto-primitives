#[macro_export]
/// Convert any serializable object to unchecked bytes.
macro_rules! to_unchecked_bytes {
    ($v: expr) => {{
        let mut bytes = Vec::new();
        let result = $v.borrow().serialize_compressed(&mut bytes);
        if let Ok(()) = result {
            Ok(bytes)
        } else {
            Err(result.err().unwrap())
        }
    }};
}

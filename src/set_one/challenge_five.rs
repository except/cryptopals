pub fn repeating_key_xor(key: &[u8], data: &mut [u8]) {
    let key_len = key.len();
    for (i, el) in data.iter_mut().enumerate() {
        *el ^= key[i % key_len];
    }
}

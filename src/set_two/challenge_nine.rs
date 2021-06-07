pub fn pad_pkcs7(block: &mut Vec<u8>, block_size: u8, pad_byte: u8) {
    assert!(block.len() <= block_size as usize);
    block.extend((0..block_size - block.len() as u8).map(|_| pad_byte));
}

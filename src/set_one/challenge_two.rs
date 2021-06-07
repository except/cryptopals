pub fn fixed_xor(x: &mut [u8], y: &[u8]) {
    assert_eq!(x.len(), y.len());

    for i in 0..x.len() {
        x[i] ^= y[i]
    }
}

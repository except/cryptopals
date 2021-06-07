pub mod challenge_nine;
pub mod challenge_ten;

#[cfg(test)]
mod tests {
    #[test]
    fn pad_pkcs7_9() {
        let mut data = "YELLOW SUBMARINE".as_bytes().to_vec();
        super::challenge_nine::pad_pkcs7(&mut data, 20, 4);

        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(), &data);
    }
}
